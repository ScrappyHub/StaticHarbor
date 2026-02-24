#!/usr/bin/env python3
# StaticHarbor (Tier-0) â€” safe defensive engine
# - Ethics gate required for remote actions (scan)
# - listen = local test harness (TCP/UDP), not a sniffer

import argparse, json, os, socket, sys, threading, time
from typing import Dict, Any, List, Optional

APP="StaticHarbor"
ACK_DIR=os.path.join(os.path.expanduser("~"), ".static_harbor")
ACK_PATH=os.path.join(ACK_DIR, "ethics_ack.json")
ECHO_STATIC_BYTES = b"STATIC_HARBOR_ECHO_V1\n"

def jdump(obj: Dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(obj, sort_keys=True, indent=2) + "\n")

def ensure_dir(p: str) -> None:
    if not p: raise RuntimeError("EMPTY_PATH")
    if not os.path.isdir(p): os.makedirs(p, exist_ok=True)

def ethics_required() -> bool:
    return os.path.isfile(ACK_PATH)

def cmd_ethics(_args: argparse.Namespace) -> int:
    print("StaticHarbor Ethics Gate")
    print("------------------------------")
    goal = input("What are you running / what is your goal?\\n").strip()
    targets = input("What target(s) will you test (authorized only)?\\n").strip()
    perm = input("Do you have explicit permission? (yes/no) ").strip().lower()
    if perm != "yes": print("DENY: permission required."); return 2
    scope = input("Are you staying within scope? (yes/no) ").strip().lower()
    if scope != "yes": print("DENY: scope required."); return 2
    ensure_dir(ACK_DIR)
    ack={"schema":"static_harbor.ethics_ack.v1","ok":True,"goal":goal,"targets":targets,"permission":True,"scope":True}
    with open(ACK_PATH,"w",encoding="utf-8",newline="\n") as f: f.write(json.dumps(ack, sort_keys=True, indent=2) + "\n")
    print("OK: ethics acknowledged -> " + ACK_PATH)
    return 0

def score_password(pw: str) -> Dict[str, Any]:
    length=len(pw)
    has_lower=any("a"<=c<="z" for c in pw)
    has_upper=any("A"<=c<="Z" for c in pw)
    has_digit=any("0"<=c<="9" for c in pw)
    has_sym=any(not c.isalnum() for c in pw)
    classes=sum([has_lower,has_upper,has_digit,has_sym])
    score=0
    score += 2 if length>=12 else (1 if length>=8 else 0)
    score += classes
    verdict="weak"
    if score>=5: verdict="strong"
    elif score>=3: verdict="ok"
    return {"schema":"static_harbor.pw_score.v1","length":length,"has_lower":has_lower,"has_upper":has_upper,"has_digit":has_digit,"has_symbol":has_sym,"classes":classes,"score":score,"verdict":verdict}

def cmd_pw_check(args: argparse.Namespace) -> int:
    pw=args.password if args.password is not None else input("Password (will be echoed): ").rstrip("\\n")
    jdump(score_password(pw)); return 0

def cmd_pw_gen(args: argparse.Namespace) -> int:
    import secrets, string
    alpha=string.ascii_letters+string.digits
    syms="!@#$%^&*()-_=+[]{}:,.?"
    charset=alpha+(syms if args.symbols else "")
    pw="".join(secrets.choice(charset) for _ in range(int(args.length)))
    jdump({"schema":"static_harbor.pw_gen.v1","length":int(args.length),"symbols":bool(args.symbols),"password":pw}); return 0

def parse_ports(spec: str) -> List[int]:
    out=[]
    parts=[p.strip() for p in (spec or "").split(",") if p.strip()]
    for p in parts:
        if "-" in p:
            a,b=p.split("-",1); a=int(a.strip()); b=int(b.strip())
            if a<1 or b<1 or b<a: raise ValueError("BAD_RANGE")
            out.extend(list(range(a,b+1)))
        else:
            v=int(p);
            if v<1: raise ValueError("BAD_PORT")
            out.append(v)
    seen=set(); ded=[]
    for x in out:
        if x not in seen: seen.add(x); ded.append(x)
    return ded

def tcp_probe(host: str, port: int, timeout_ms: int) -> bool:
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout_ms/1000.0)
        return s.connect_ex((host, port))==0
    except Exception:
        return False
    finally:
        try: s.close()
        except Exception: pass

def cmd_scan(args: argparse.Namespace) -> int:
    if not ethics_required(): print("ETHICS_REQUIRED: run ethics first."); return 2
    ports=parse_ports(args.ports)
    host=args.host
    timeout_ms=int(args.timeout_ms)
    threads_req=int(args.threads)
    t0=time.time()
    openp=[]; closedp=[]
    lock=threading.Lock(); idx={"i":0}
    def worker():
        while True:
            with lock:
                if idx["i"]>=len(ports): return
                p=ports[idx["i"]]; idx["i"]+=1
            ok=tcp_probe(host,p,timeout_ms)
            with lock:
                (openp if ok else closedp).append(p)
    worker_count=max(1, min(threads_req, len(ports)))
    ws=[]
    for _ in range(worker_count):
        th=threading.Thread(target=worker, daemon=True); ws.append(th); th.start()
    for th in ws: th.join()
    openp.sort(); closedp.sort()
    elapsed=time.time()-t0
    jdump({"schema":"static_harbor.scan_result.v1","host":host,"timeout_ms":timeout_ms,"threads":worker_count,"open_ports":openp,"closed_ports":closedp,"elapsed_sec":round(elapsed,4),"scanned":len(ports)})
    return 0

def _write_log_line(path: str, obj: Dict[str, Any]) -> None:
    with open(path,"a",encoding="utf-8",newline="\n") as f: f.write(json.dumps(obj, sort_keys=True) + "\n")

def cmd_listen(args: argparse.Namespace) -> int:
    bind_host=args.bind
    tcp_port=args.tcp
    udp_port=args.udp
    echo_mode=args.echo_mode
    log_path=args.log
    if tcp_port is None and udp_port is None: print("ERR: choose --tcp or --udp"); return 2
    if tcp_port is not None and udp_port is not None: print("ERR: choose only one: --tcp or --udp"); return 2
    if log_path:
        parent=os.path.dirname(os.path.abspath(log_path))
        if parent: ensure_dir(parent)
    def mk_echo(payload: bytes) -> bytes:
        if echo_mode=="mirror": return payload
        return ECHO_STATIC_BYTES
    if tcp_port is not None:
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((bind_host, int(tcp_port)))
        s.listen(16)
        print(f"LISTEN_TCP_OK: {bind_host}:{tcp_port}")
        print("CTRL_C to stop.")
        try:
            while True:
                conn,addr=s.accept()
                try:
                    conn.settimeout(2.0)
                    try: data=conn.recv(int(args.max_bytes))
                    except Exception: data=b""
                    resp=mk_echo(data)
                    if args.echo:
                        try: conn.sendall(resp)
                        except Exception: pass
                    if log_path:
                        _write_log_line(log_path, {"schema":"static_harbor.listen_event.v1","proto":"tcp","bind":bind_host,"port":int(tcp_port),"peer":f"{addr[0]}:{addr[1]}","rx_len":int(len(data)),"tx_len":int(len(resp) if args.echo else 0)})
                finally:
                    try: conn.close()
                    except Exception: pass
        except KeyboardInterrupt:
            print("LISTEN_STOP: tcp"); return 0
        finally:
            try: s.close()
            except Exception: pass
    if udp_port is not None:
        s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((bind_host, int(udp_port)))
        print(f"LISTEN_UDP_OK: {bind_host}:{udp_port}")
        print("CTRL_C to stop.")
        try:
            while True:
                data,addr=s.recvfrom(int(args.max_bytes))
                resp=mk_echo(data)
                if args.echo:
                    try: s.sendto(resp, addr)
                    except Exception: pass
                if log_path:
                    _write_log_line(log_path, {"schema":"static_harbor.listen_event.v1","proto":"udp","bind":bind_host,"port":int(udp_port),"peer":f"{addr[0]}:{addr[1]}","rx_len":int(len(data)),"tx_len":int(len(resp) if args.echo else 0)})
        except KeyboardInterrupt:
            print("LISTEN_STOP: udp"); return 0
        finally:
            try: s.close()
            except Exception: pass
    return 0

# --- http-listen (learning tool) ---
HTTP_STATIC_BODY = b"STATIC_HARBOR_HTTP_V1\n"

def _http_mk_body(mode: str, raw_req: bytes) -> bytes:
    if mode == "mirror":
        return raw_req[:4096] if raw_req else b""
    return HTTP_STATIC_BODY

def cmd_http_listen(args: argparse.Namespace) -> int:
    # Local HTTP lab server (TCP). Not a scanner. Not a sniffer.
    bind_host = args.bind
    tcp_port = int(args.tcp)
    log_path = args.log
    echo_mode = args.echo_mode
    max_bytes = int(args.max_bytes)
    once = bool(args.once)

    if log_path:
        parent = os.path.dirname(os.path.abspath(log_path))
        if parent:
            ensure_dir(parent)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind_host, tcp_port))
    s.listen(16)
    print(f"HTTP_LISTEN_OK: {bind_host}:{tcp_port}")
    print("CTRL_C to stop.")

    try:
        handled = 0
        while True:
            conn, addr = s.accept()
            try:
                conn.settimeout(2.0)
                raw = b""
                try:
                    raw = conn.recv(max_bytes)
                except Exception:
                    raw = b""

                body = _http_mk_body(echo_mode, raw)
                headers = [
                    b"HTTP/1.1 200 OK",
                    b"Content-Type: text/plain; charset=utf-8",
                    b"Content-Length: " + str(len(body)).encode("ascii"),
                    b"Connection: close",
                    b"",
                    b""
                ]
                resp = b"\r\n".join(headers) + body
                try:
                    conn.sendall(resp)
                except Exception:
                    pass

                if log_path:
                    _write_log_line(log_path, {
                        "schema": "static_harbor.http_listen_event.v1",
                        "proto": "tcp",
                        "bind": bind_host,
                        "port": int(tcp_port),
                        "peer": f"{addr[0]}:{addr[1]}",
                        "rx_len": int(len(raw)),
                        "tx_len": int(len(resp))
                    })

                handled += 1
                if once and handled >= 1:
                    return 0
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
    except KeyboardInterrupt:
        print("HTTP_LISTEN_STOP")
        return 0
    finally:
        try:
            s.close()
        except Exception:
            pass

def cmd_gui(_args: argparse.Namespace) -> int:
    here=os.path.dirname(os.path.abspath(__file__))
    gui=os.path.join(here, "static_harbor_gui.py")
    if not os.path.isfile(gui): print("GUI_MISSING: " + gui); return 2
    import importlib.util
    spec=importlib.util.spec_from_file_location("static_harbor_gui", gui)
    if spec is None or spec.loader is None: print("GUI_IMPORT_FAILED"); return 2
    mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    if hasattr(mod,"main"): return int(mod.main() or 0)
    print("GUI_NO_MAIN"); return 2
def build_parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(prog=APP, description="StaticHarbor (safe defensive engine)")
    sub=p.add_subparsers(dest="cmd", required=True)

    s=sub.add_parser("ethics"); s.set_defaults(fn=cmd_ethics)

    s=sub.add_parser("pw-check")
    s.add_argument("--password", default=None)
    s.set_defaults(fn=cmd_pw_check)

    s=sub.add_parser("pw-gen")
    s.add_argument("--length", type=int, default=16)
    s.add_argument("--symbols", action="store_true")
    s.set_defaults(fn=cmd_pw_gen)

    s=sub.add_parser("scan")
    s.add_argument("--host", required=True)
    s.add_argument("--ports", required=True)
    s.add_argument("--timeout-ms", dest="timeout_ms", type=int, default=500)
    s.add_argument("--threads", type=int, default=64)
    s.set_defaults(fn=cmd_scan)

    s=sub.add_parser("listen")
    s.add_argument("--bind", default="0.0.0.0")
    s.add_argument("--tcp", type=int, default=None)
    s.add_argument("--udp", type=int, default=None)
    s.add_argument("--echo", action="store_true")
    s.add_argument("--echo-mode", dest="echo_mode", choices=["static","mirror"], default="static")
    s.add_argument("--max-bytes", dest="max_bytes", type=int, default=4096)
    s.add_argument("--log", default=None)
    s.set_defaults(fn=cmd_listen)

    s=sub.add_parser("http-listen", help="Local HTTP lab server (TCP). Learning tool. Not a scanner.")
    s.add_argument("--bind", default="127.0.0.1", help="bind address (default 127.0.0.1)")
    s.add_argument("--tcp", type=int, required=True, help="listen TCP port")
    s.add_argument("--echo-mode", dest="echo_mode", choices=["static","mirror"], default="static")
    s.add_argument("--max-bytes", dest="max_bytes", type=int, default=4096)
    s.add_argument("--log", default=None, help="append-only jsonl event log path (optional)")
    s.add_argument("--once", action="store_true", help="accept a single request then exit (for smoke tests)")
    s.set_defaults(fn=cmd_http_listen)

    s=sub.add_parser("gui"); s.set_defaults(fn=cmd_gui)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser=build_parser(); args=parser.parse_args(argv)
    fn=getattr(args,"fn",None)
    if fn is None: return 2
    return int(fn(args) or 0)

if __name__=="__main__": raise SystemExit(main())
