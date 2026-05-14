
StaticHarbor Specification v1
Purpose

StaticHarbor is a safe defensive networking and learning instrument.

It exists to let a user start controlled local service harnesses, observe network interaction behavior, emit deterministic evidence, and run reproducible selftests.

Tier-0 meaning

Tier-0 means StaticHarbor stands on its own as a local instrument. It does not mean transport-layer-only.

Tier-0 requires:

no external service required for correctness
deterministic runners
parse-gated PowerShell scripts
Python compile gate
append-only evidence
explicit success tokens
no false green behavior
Allowed capabilities
TCP local listener
UDP local listener
HTTP local listener
authorized TCP connect scanning
password utility checks
receipt-backed event emission
deterministic smoke testing
Forbidden capabilities
exploit automation
credential theft
malware behavior
stealth persistence
unauthorized scanning
packet sniffing without explicit future governance
destructive network actions
Current success tokens
LISTEN_SMOKE_TCP_OK
LISTEN_SMOKE_UDP_OK
STATIC_HARBOR_LISTEN_SMOKE_OK
STATIC_HARBOR_HTTP_LISTEN_SMOKE_OK
STATIC_HARBOR_TIER0_FULL_GREEN_OK
Next build lanes
Event schema validation runner
Receipt chain verifier
Session ID and run ID normalization
IDS-ready local rule hooks
Dashboard/read-only event viewer
Golden vectors for event and receipt logs
