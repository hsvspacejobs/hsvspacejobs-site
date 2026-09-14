#!/usr/bin/env bash
# Refresh jobs.json from GitHub main so `wrangler deploy` cannot upload a missing/stale feed.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
echo "Fetching current jobs.json from hsvspacejobs/hsvspacejobs-site@main ..."
curl -fsSL "https://raw.githubusercontent.com/hsvspacejobs/hsvspacejobs-site/main/jobs.json" -o jobs.json
python3 - <<'PY'
import json
from pathlib import Path
data=json.loads(Path('jobs.json').read_text())
assert 'jobs' in data and isinstance(data['jobs'], list)
print(f"OK: jobs.json ready with {len(data['jobs'])} jobs (not for commit unless unchanged on remote).")
PY
