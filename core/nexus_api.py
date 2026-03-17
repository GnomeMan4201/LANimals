from __future__ import annotations

from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse

from core.nexus_builder import build_snapshot

ROOT = Path(__file__).resolve().parent.parent
UI_FILE = ROOT / "ui" / "lanimals_live_map.html"
REPORTS_DIR = ROOT / "reports"

app = FastAPI(title="LANimals Live Map", version="0.2.0")


@app.get("/api/graph")
def get_graph():
    snapshot = build_snapshot()
    return JSONResponse(snapshot.model_dump())


@app.get("/api/node/{node_id:path}")
def get_node(node_id: str):
    snapshot = build_snapshot()

    node = next((n for n in snapshot.nodes if n.id == node_id), None)
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")

    related_edges = [
        e for e in snapshot.edges
        if e.source == node_id or e.target == node_id
    ]

    neighbor_ids = set()
    for e in related_edges:
        if e.source != node_id:
            neighbor_ids.add(e.source)
        if e.target != node_id:
            neighbor_ids.add(e.target)

    neighbors = [n for n in snapshot.nodes if n.id in neighbor_ids]
    related_events = [evt for evt in snapshot.events if evt.node_id == node_id]

    return JSONResponse({
        "node": node.model_dump(),
        "neighbors": [n.model_dump() for n in neighbors],
        "edges": [e.model_dump() for e in related_edges],
        "events": [e.model_dump() for e in related_events],
    })


@app.get("/api/reports")
def get_reports():
    files = []
    if REPORTS_DIR.exists():
        for path in sorted(REPORTS_DIR.glob("report_*.json"), reverse=True):
            stat = path.stat()
            files.append({
                "name": path.name,
                "size": stat.st_size,
                "modified": stat.st_mtime,
            })
    return {"reports": files[:20]}


@app.get("/api/health")
def health():
    return {"ok": True, "service": "lanimals-live-map"}


@app.get("/favicon.ico")
def favicon():
    favicon_path = ROOT / "assets" / "LANimals.png"
    if favicon_path.exists():
        return FileResponse(favicon_path)
    raise HTTPException(status_code=404, detail="No favicon")


@app.get("/")
def ui():
    return FileResponse(UI_FILE)
