from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class GraphNode(BaseModel):
    id: str
    node_type: str
    label: str
    status: str = "normal"
    risk_score: int = 0
    ip: Optional[str] = None
    mac: Optional[str] = None
    hostname: Optional[str] = None
    group: Optional[str] = None
    meta: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    edge_type: str = "connected_to"
    status: str = "normal"
    weight: float = 1.0
    meta: Dict[str, Any] = Field(default_factory=dict)


class GraphEvent(BaseModel):
    id: str
    ts: str
    severity: str
    title: str
    summary: str
    node_id: Optional[str] = None


class GraphSnapshot(BaseModel):
    title: str
    subtitle: str
    generated_at: str
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    events: List[GraphEvent]
    stats: Dict[str, Any] = Field(default_factory=dict)
