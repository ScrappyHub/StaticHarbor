# StaticHarbor

StaticHarbor is a standalone defensive networking lab and evidence instrument.

It provides safe local TCP, UDP, and HTTP service harnesses, basic authorized TCP scanning, password utilities, append-only event logs, receipt chains, and deterministic smoke runners.

StaticHarbor is not an exploit framework, malware tool, credential harvester, packet sniffer, or offensive automation platform.

## Current proven surface

- TCP listen harness
- UDP listen harness
- HTTP listen harness
- Static and mirror echo modes
- Append-only JSONL event logs
- Receipt chain files
- TCP/UDP/HTTP smoke runners
- Tier-0 full-green runner
- Ethics gate for scan mode
- Basic TCP connect scanning
- Password check and password generation utilities

## Run

```powershell
python .\static_harbor_engine.py --help
python .\static_harbor_engine.py listen --help
python .\static_harbor_engine.py http-listen --help
Full green
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\scripts\_RUN_static_harbor_tier0_full_green_v1.ps1 -RepoRoot .

Expected success token:

STATIC_HARBOR_TIER0_FULL_GREEN_OK
Evidence

Generated runtime proof files are written under:

proofs/receipts/

These files are local run outputs and are ignored by Git unless intentionally promoted as golden vectors.
