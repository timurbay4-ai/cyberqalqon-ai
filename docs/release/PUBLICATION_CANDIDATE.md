# CyberQalqon source publication candidate

M37 prepares the M36 implementation for review. This tree contains first-party
application source, tests, contracts, build metadata and safe operational guides.
Historical private/raw milestone evidence stays in the original local workspace;
it is not a build dependency. The CDRCv2 compatibility baseline is an explicitly
synthetic required test fixture. No private runtime data or compiler is included.

Build prerequisites: Python 3.11, Go 1.27.0, Node 24.15.0 and npm 11.12.1.
Use backend/requirements-build.txt and requirements-dev.txt; Windows/Python3.11
constraints are backend/constraints-py311-windows.txt. Install the first-party
sender from ./wazuh. Set process PYTHONPATH to root, backend, wazuh and scripts.
CYBERQALQON_GO may point to an explicit Go SDK; ordinary CGO_ENABLED=0 builds
need no C compiler. Race tests require a separately verified compatible compiler.
No private ignored folder from the original workstation is a source dependency.

Run pytest for backend/tests, wazuh/tests and tests; run Go test, vet and race
for collector; npm ci, typecheck, tests and build in frontend. CI contains the
corresponding jobs, but remote execution is NOT_RUN until an authorized push/PR.

The last M36 source validation had 1528 unique cases and 144 repeated race
executions. M37 fresh results and package hashes are supplied in the external
review packet. Strict SAST remains BLOCKED_PENDING_INDEPENDENT_REVIEW; no waiver
is approved. M33 performance acceptance remains DEFERRED with its unchanged
p95 ratio threshold 1.25. Browser UAT is DEFERRED_BY_USER; real telemetry is
NOT_LIVE_VALIDATED. AI remains false, DET001вЂ“009 disabled/shadow-only, retention
100000/30 days, schema17/history1 and batch disabled. Historical continuity is
UNPROVEN. This tree is NOT_DEPLOYED and is not authorization to publish.

Git branch/stage, commit, push, draft PR, merge and deployment each require
separate explicit operator approval. Preserve the existing worktree and history.

CI also binds the complete Git tree and file content to the reviewed publication
manifest. New, removed or modified files require an explicit regenerated manifest
and review; this is a release snapshot check, not a general moving development
branch policy. The manifest excludes its own content row to avoid circular hashes.
Its own hash is bound externally by the local review packet; no signature or
independent security approval is claimed by a checksum.

Publication text is canonical LF; .gitattributes fixes checkout EOL for Windows
and Linux. Original local source bytes remain preserved. EOL-only normalization
is separately inventoried; it does not alter parsed application code or fixtures.
