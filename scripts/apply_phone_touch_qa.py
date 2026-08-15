from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected exactly one anchor in {path}, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


css = ROOT / "docs" / "app.css"
js = ROOT / "docs" / "app.js"
tests = ROOT / "tests" / "test_public_pages_console.py"

replace_once(
    css,
    '.graph-node { cursor: pointer; outline: none; }\n.graph-node circle.node-ring',
    '.graph-node { cursor: pointer; outline: none; }\n.graph-node circle.node-hit { fill: transparent; stroke: none; pointer-events: all; }\n.graph-node circle.node-ring',
)

replace_once(
    css,
    '  .mode-badge { font-size: 8px; padding: 5px 7px; }\n  .mobile-icon {',
    '  .mode-badge { font-size: 8px; padding: 5px 7px; }\n  .topology-wrap { grid-template-rows: 52px 1fr; }\n  .topology-toolbar { padding: 4px 9px; }\n  .search-wrap input { height: 44px; }\n  .toolbar-button { min-width: 44px; height: 44px; }\n  .evidence-drawer { grid-template-rows: 45px 1fr; }\n  .tab { height: 44px; min-height: 44px; }\n  .op-button { min-height: 44px; }\n  .small-button { min-height: 44px; }\n  .terminal-shell { grid-template-rows: 1fr 44px; }\n  .terminal-input-row, #terminalInput { min-height: 44px; }\n  .mobile-icon {',
)

replace_once(
    css,
    '    width: 36px;\n    height: 36px;',
    '    width: 44px;\n    height: 44px;',
)

replace_once(
    css,
    '  .topology-toolbar { padding: 7px 9px; gap: 7px; }',
    '  .topology-toolbar { gap: 7px; }',
)

replace_once(
    js,
    '      group.appendChild(svgEl("circle", { class: "node-ring", r: 18 }));',
    '      group.appendChild(svgEl("circle", { class: "node-hit", r: 24 }));\n      group.appendChild(svgEl("circle", { class: "node-ring", r: 18 }));',
)

append = '''\n\ndef test_phone_touch_targets_are_thumb_sized_without_inflating_desktop():\n    mobile = APP_CSS.split("@media (max-width: 760px)", 1)[1].split("@media (max-width: 460px)", 1)[0]\n    assert ".mobile-icon" in mobile and "width: 44px" in mobile and "height: 44px" in mobile\n    assert ".op-button { min-height: 44px; }" in mobile\n    assert ".small-button { min-height: 44px; }" in mobile\n    assert ".tab { height: 44px; min-height: 44px; }" in mobile\n    assert ".search-wrap input { height: 44px; }" in mobile\n    assert ".toolbar-button { min-width: 44px; height: 44px; }" in mobile\n    assert ".terminal-input-row, #terminalInput { min-height: 44px; }" in mobile\n    assert 'class: "node-hit", r: 24' in APP_JS\n    assert ".graph-node circle.node-hit" in APP_CSS\n'''
text = tests.read_text(encoding="utf-8")
if "test_phone_touch_targets_are_thumb_sized_without_inflating_desktop" in text:
    raise SystemExit("phone touch regression test already present")
tests.write_text(text.rstrip() + append.rstrip() + "\n", encoding="utf-8")
