#!/usr/bin/env python3
import argparse
import datetime
import hashlib
import json
import os
import secrets
import socket
import string
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional

APP = "StaticHarbor"
ACK_DIR = os.path.join(os.path.expanduser("~"), ".static_harbor")
ACK_PATH = os.path.join(ACK_DIR, "ethics_ack.json")
ECHO_STATIC_BYTES = b"STATIC_HARBOR_ECHO_V1\n"
HTTP_STATIC_BODY = b"STATIC_HARBOR_HTTP_V1\n"

def ensure_dir(path: str) -> None:
    if path and not os.path.isdir(path):
        os.makedirs(path, exist_ok=True)

def canonical_json(obj: Dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))

def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def write_jsonl(path: str, obj: Dict[str, Any]) -> None:
    path = os.path.abspath(path)
    ensure_dir(os.path.dirname(path))
    with open(path, "a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(obj, sort_keys=True) + "\n")

def read_prev_receipt_hash(path: str) -> Optional[str]:
    if not os.path.isfile(path):
        return None
    last = None
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                last = line
    if not last:
        return None
    try:
        return json.loads(last).get("receipt_sha256")
    except Exception:
        return None

def append_receipt(log_path: str, event: Dict[str, Any]) -> None:
    receipt_log = os.path.abspath(log_path) + ".receipts.jsonl"
    event_line = canonical_json(event)
    event_hash = sha256_text(event_line)
    prev_hash = read_prev_receipt_hash(receipt_log)
    receipt = {
        "schema": "static_harbor.receipt_event.v1",
        "ts_utc": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "event_type": str(event.get("schema", "unknown")),
        "event_sha256": event_hash,
        "prev_receipt_sha256": prev_hash
    }
    receipt["receipt_sha256"] = sha256_text(canonical_json(receipt))
    write_jsonl(receipt_log, receipt)

def append_event(log_path: Optional[str], event: Dict[str, Any]) -> None:
    if not log_path:
        return
    write_jsonl(log_path, event)
    append_receipt(log_path, event)

def jdump(obj: Dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(obj, sort_keys=True, indent=2) + "\n")

def ethics_required() -> bool:
    return os.path.isfile(ACK_PATH)

def cmd_ethics(_args: argparse.Namespace) -> int:
    print("StaticHarbor Ethics Gate")
    print("------------------------------")
    goal = input("What are you running / what is your goal?\n").strip()
    targets = input("What target(s) will you test (authorized only)?\n").strip()
    perm = input("Do you have explicit permission? (yes/no) ").strip().lower()
    if perm != "yes":
        print("DENY: permission required.")
        return 2
    scope = input("Are you staying within scope? (yes/no) ").strip().lower()
    if scope != "yes":
        print("DENY: scope required.")
        return 2
    ensure_dir(ACK_DIR)
    ack = {"schema":"static_harbor.ethics_ack.v1","ok":True,"goal":goal,"targets":targets,"permission":True,"scope":True}
    with open(ACK_PATH,"w",encoding="utf-8",newline="\n") as f:
        f.write(json.dumps(ack, sort_keys=True, indent=2) + "\n")
    print("OK: ethics acknowledged -> " + ACK_PATH)
    return 0

def cmd_pw_check(args: argparse.Namespace) -> int:
    pw = args.password if args.password is not None else input("Password (will be echoed): ").rstrip("\n")
    classes = sum([
        any("a" <= c <= "z" for c in pw),
        any("A" <= c <= "Z" for c in pw),
        any("0" <= c <= "9" for c in pw),
        any(not c.isalnum() for c in pw)
    ])
    score = (2 if len(pw) >= 12 else (1 if len(pw) >= 8 else 0)) + classes
    verdict = "strong" if score >= 5 else ("ok" if score >= 3 else "weak")
    jdump({"schema":"static_harbor.pw_score.v1","length":len(pw),"classes":classes,"score":score,"verdict":verdict})
    return 0

def cmd_pw_gen(args: argparse.Namespace) -> int:
    chars = string.ascii_letters + string.digits + ("!@#$%^&*()-_=+[]{}:,.?" if args.symbols else "")
    pw = "".join(secrets.choice(chars) for _ in range(int(args.length)))
    jdump({"schema":"static_harbor.pw_gen.v1","length":int(args.length),"symbols":bool(args.symbols),"password":pw})
    return 0

def parse_ports(spec: str) -> List[int]:
    out: List[int] = []
    for part in [p.strip() for p in spec.split(",") if p.strip()]:
        if "-" in part:
            a,b = part.split("-",1)
            out.extend(range(int(a), int(b)+1))
        else:
            out.append(int(part))
    seen = set()
    dedup = []
    for p in out:
        if p < 1 or p > 65535:
            raise ValueError("BAD_PORT")
        if p not in seen:
            seen.add(p)
            dedup.append(p)
    return dedup

def cmd_scan(args: argparse.Namespace) -> int:
    if not ethics_required():
        print("ETHICS_REQUIRED: run ethics first.")
        return 2
    ports = parse_ports(args.ports)
    open_ports = []
    closed_ports = []
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(int(args.timeout_ms)/1000.0)
            ok = s.connect_ex((args.host,p)) == 0
            (open_ports if ok else closed_ports).append(p)
        finally:
            s.close()
    jdump({"schema":"static_harbor.scan_result.v1","host":args.host,"open_ports":open_ports,"closed_ports":closed_ports,"scanned":len(ports)})
    return 0

def cmd_listen(args: argparse.Namespace) -> int:
    if args.tcp is None and args.udp is None:
        print("ERR: choose --tcp or --udp")
        return 2
    if args.tcp is not None and args.udp is not None:
        print("ERR: choose only one")
        return 2

    def mk_echo(data: bytes) -> bytes:
        return data if args.echo_mode == "mirror" else ECHO_STATIC_BYTES

    if args.tcp is not None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((args.bind, int(args.tcp)))
        srv.listen(16)
        print(f"LISTEN_TCP_OK: {args.bind}:{args.tcp}", flush=True)
        print("CTRL_C to stop.", flush=True)
        try:
            while True:
                conn, addr = srv.accept()
                try:
                    conn.settimeout(2.0)
                    try:
                        data = conn.recv(int(args.max_bytes))
                    except Exception:
                        data = b""
                    resp = mk_echo(data)
                    if args.echo:
                        conn.sendall(resp)
                    event = {"schema":"static_harbor.listen_event.v1","proto":"tcp","bind":args.bind,"port":int(args.tcp),"peer":f"{addr[0]}:{addr[1]}","rx_len":len(data),"tx_len":len(resp) if args.echo else 0}
                    append_event(args.log, event)
                finally:
                    conn.close()
        except KeyboardInterrupt:
            print("LISTEN_STOP: tcp")
            return 0
        finally:
            srv.close()

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind((args.bind, int(args.udp)))
    print(f"LISTEN_UDP_OK: {args.bind}:{args.udp}", flush=True)
    print("CTRL_C to stop.", flush=True)
    try:
        while True:
            data, addr = udp.recvfrom(int(args.max_bytes))
            resp = mk_echo(data)
            if args.echo:
                udp.sendto(resp, addr)
            event = {"schema":"static_harbor.listen_event.v1","proto":"udp","bind":args.bind,"port":int(args.udp),"peer":f"{addr[0]}:{addr[1]}","rx_len":len(data),"tx_len":len(resp) if args.echo else 0}
            append_event(args.log, event)
    except KeyboardInterrupt:
        print("LISTEN_STOP: udp")
        return 0
    finally:
        udp.close()

def cmd_http_listen(args: argparse.Namespace) -> int:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.bind, int(args.tcp)))
    srv.listen(16)
    print(f"HTTP_LISTEN_OK: {args.bind}:{args.tcp}", flush=True)
    print("CTRL_C to stop.", flush=True)
    handled = 0
    try:
        while True:
            conn, addr = srv.accept()
            try:
                conn.settimeout(2.0)
                try:
                    raw = conn.recv(int(args.max_bytes))
                except Exception:
                    raw = b""
                body = raw[:4096] if args.echo_mode == "mirror" else HTTP_STATIC_BODY
                headers = [
                    b"HTTP/1.1 200 OK",
                    b"Content-Type: text/plain; charset=utf-8",
                    b"Content-Length: " + str(len(body)).encode("ascii"),
                    b"Connection: close",
                    b"",
                    b""
                ]
                resp = b"\r\n".join(headers) + body
                conn.sendall(resp)
                event = {"schema":"static_harbor.http_listen_event.v1","proto":"tcp","bind":args.bind,"port":int(args.tcp),"peer":f"{addr[0]}:{addr[1]}","rx_len":len(raw),"tx_len":len(resp)}
                append_event(args.log, event)
                handled += 1
                if args.once and handled >= 1:
                    return 0
            finally:
                conn.close()
    except KeyboardInterrupt:
        print("HTTP_LISTEN_STOP")
        return 0
    finally:
        srv.close()

def cmd_gui(_args: argparse.Namespace) -> int:
    print("GUI not tracked in current core surface.")
    return 0

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=APP, description="StaticHarbor (safe defensive engine)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("ethics"); s.set_defaults(fn=cmd_ethics)
    s = sub.add_parser("pw-check"); s.add_argument("--password", default=None); s.set_defaults(fn=cmd_pw_check)
    s = sub.add_parser("pw-gen"); s.add_argument("--length", type=int, default=16); s.add_argument("--symbols", action="store_true"); s.set_defaults(fn=cmd_pw_gen)

    s = sub.add_parser("scan")
    s.add_argument("--host", required=True)
    s.add_argument("--ports", required=True)
    s.add_argument("--timeout-ms", dest="timeout_ms", type=int, default=500)
    s.add_argument("--threads", type=int, default=64)
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("listen")
    s.add_argument("--bind", default="0.0.0.0")
    s.add_argument("--tcp", type=int, default=None)
    s.add_argument("--udp", type=int, default=None)
    s.add_argument("--echo", action="store_true")
    s.add_argument("--echo-mode", dest="echo_mode", choices=["static","mirror"], default="static")
    s.add_argument("--max-bytes", dest="max_bytes", type=int, default=4096)
    s.add_argument("--log", default=None)
    s.set_defaults(fn=cmd_listen)

    s = sub.add_parser("http-listen")
    s.add_argument("--bind", default="127.0.0.1")
    s.add_argument("--tcp", type=int, required=True)
    s.add_argument("--echo-mode", dest="echo_mode", choices=["static","mirror"], default="static")
    s.add_argument("--max-bytes", dest="max_bytes", type=int, default=4096)
    s.add_argument("--log", default=None)
    s.add_argument("--once", action="store_true")
    s.set_defaults(fn=cmd_http_listen)

    s = sub.add_parser("gui"); s.set_defaults(fn=cmd_gui)
    return p

def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.fn(args) or 0)

if __name__ == "__main__":
    raise SystemExit(main())
