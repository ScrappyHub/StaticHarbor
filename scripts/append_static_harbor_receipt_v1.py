import sys, json, hashlib, os, datetime

def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def read_last_hash(path: str):
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            pos = f.tell()
            if pos == 0:
                return None
            while pos > 0:
                pos -= 1
                f.seek(pos)
                if f.read(1) == b"\n":
                    break
            line = f.readline().decode("utf-8").strip()
            if not line:
                return None
            obj = json.loads(line)
            return obj.get("receipt_sha256")
    except:
        return None

def main():
    log = sys.argv[sys.argv.index("--log")+1]

    raw = sys.stdin.read()
    if not raw:
        print("EMPTY", file=sys.stderr)
        return 1

    obj = json.loads(raw)
    canon = json.dumps(obj, sort_keys=True)

    event_hash = sha256(canon)
    prev = read_last_hash(log)

    receipt = {
        "schema": "static_harbor.receipt_event.v1",
        "ts_utc": datetime.datetime.utcnow().isoformat() + "Z",
        "event_type": obj.get("schema","unknown"),
        "event_sha256": event_hash,
        "prev_receipt_sha256": prev
    }

    receipt["receipt_sha256"] = sha256(json.dumps(receipt, sort_keys=True))

    os.makedirs(os.path.dirname(log), exist_ok=True)

    with open(log,"a",encoding="utf-8",newline="\n") as f:
        f.write(json.dumps(receipt, sort_keys=True) + "\n")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
