from pathlib import Path

path = Path("core/nexus_collectors.py")
text = path.read_text(encoding="utf-8")
old = "import subprocess\nfrom typing import Any, Dict, List\n"
new = "import subprocess\nfrom pathlib import Path\nfrom typing import Any, Dict, List\n"
if text.count(old) != 1:
    raise SystemExit(f"unexpected import shape: {text.count(old)} matches")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
