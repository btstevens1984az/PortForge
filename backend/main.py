from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI(
    title="PortForge API",
    description="Interactive port encyclopedia, firewall rule documentation, and conflict detection.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DATA_FILE = Path(__file__).resolve().parent / "data" / "ports.json"


class PortEntry(BaseModel):
    port: int
    proto: str
    service: str
    risk: Literal["low", "medium", "high", "critical"]
    category: str
    note: str
    guidance: str
    aliases: list[str] = Field(default_factory=list)
    related: list[int] = Field(default_factory=list)


class FirewallRule(BaseModel):
    id: str
    name: str
    action: Literal["allow", "deny", "reject"]
    direction: Literal["inbound", "outbound", "bidirectional"]
    protocol: str
    port: str
    source: str = "any"
    destination: str = "any"
    notes: str = ""


class Conflict(BaseModel):
    id: str
    severity: Literal["info", "warning", "critical"]
    type: str
    title: str
    detail: str
    ruleIds: list[str]


class ConflictRequest(BaseModel):
    rules: list[FirewallRule]


class ExportRequest(BaseModel):
    rules: list[FirewallRule]
    format: Literal["markdown", "csv", "iptables", "asa"] = "markdown"
    title: str = "Firewall Rule Documentation"


def load_ports() -> list[dict]:
    if not DATA_FILE.exists():
        return []
    return json.loads(DATA_FILE.read_text(encoding="utf-8"))


def parse_ports(token: str) -> list[int]:
    t = token.strip().lower()
    if not t or t in {"any", "*"}:
        return [-1]
    if "-" in t and "," not in t:
        a, b = [int(x.strip()) for x in t.split("-", 1)]
        return list(range(a, min(b, a + 512) + 1))
    if "," in t:
        out: list[int] = []
        for part in t.split(","):
            out.extend(parse_ports(part))
        return out
    return [int(t)]


def ports_overlap(a: str, b: str) -> bool:
    pa, pb = parse_ports(a), parse_ports(b)
    if -1 in pa or -1 in pb:
        return True
    return bool(set(pa) & set(pb))


def endpoint_match(a: str, b: str) -> bool:
    na = (a or "any").strip().lower()
    nb = (b or "any").strip().lower()
    return na in {"any", "*"} or nb in {"any", "*"} or na == nb


def proto_compatible(a: str, b: str) -> bool:
    a, b = a.upper(), b.upper()
    if a in {"ANY", "TCP/UDP"} or b in {"ANY", "TCP/UDP"}:
        return True
    return a == b


RISKY = {23, 3389, 445, 135, 139, 5900, 2375, 6379, 9200, 27017, 11211, 10000}


def detect_conflicts(rules: list[FirewallRule]) -> list[Conflict]:
    out: list[Conflict] = []
    for i, rule in enumerate(rules):
        ports = parse_ports(rule.port)
        risky = any(p in RISKY for p in ports) or -1 in ports
        wide = (rule.source or "any").lower() in {"any", "*"} or (rule.destination or "any").lower() in {
            "any",
            "*",
        }
        if rule.action == "allow" and risky and wide:
            out.append(
                Conflict(
                    id=f"risky-{rule.id}",
                    severity="critical",
                    type="risky",
                    title="Wide allow on sensitive port(s)",
                    detail=(
                        f'Rule "{rule.name}" allows {rule.port}/{rule.protocol} with a broad '
                        "source or destination."
                    ),
                    ruleIds=[rule.id],
                )
            )
        for j in range(i + 1, len(rules)):
            other = rules[j]
            if not proto_compatible(rule.protocol, other.protocol):
                continue
            if not ports_overlap(rule.port, other.port):
                continue
            if not endpoint_match(rule.source, other.source):
                continue
            if not endpoint_match(rule.destination, other.destination):
                continue
            if rule.action == other.action and rule.direction == other.direction:
                out.append(
                    Conflict(
                        id=f"dup-{rule.id}-{other.id}",
                        severity="info",
                        type="duplicate",
                        title="Possible duplicate rules",
                        detail=f'"{rule.name}" and "{other.name}" appear redundant.',
                        ruleIds=[rule.id, other.id],
                    )
                )
            elif rule.action != other.action:
                out.append(
                    Conflict(
                        id=f"contra-{rule.id}-{other.id}",
                        severity="critical",
                        type="contradiction",
                        title="Contradictory actions",
                        detail=(
                            f'"{rule.name}" ({rule.action}) conflicts with '
                            f'"{other.name}" ({other.action}).'
                        ),
                        ruleIds=[rule.id, other.id],
                    )
                )
            else:
                out.append(
                    Conflict(
                        id=f"overlap-{rule.id}-{other.id}",
                        severity="warning",
                        type="overlap",
                        title="Overlapping coverage",
                        detail=f'"{rule.name}" overlaps "{other.name}".',
                        ruleIds=[rule.id, other.id],
                    )
                )
    return out


def to_markdown(rules: list[FirewallRule], title: str) -> str:
    lines = [
        f"# {title}",
        "",
        "Generated by **PortForge**",
        "",
        "| # | Name | Action | Dir | Proto | Port | Source | Destination |",
        "|---|------|--------|-----|-------|------|--------|-------------|",
    ]
    for i, r in enumerate(rules, 1):
        lines.append(
            f"| {i} | {r.name} | {r.action.upper()} | {r.direction} | {r.protocol} | "
            f"{r.port} | `{r.source}` | `{r.destination}` |"
        )
    lines.append("")
    return "\n".join(lines)


def to_csv(rules: list[FirewallRule]) -> str:
    header = "name,action,direction,protocol,port,source,destination,notes"
    rows = [
        ",".join(
            f'"{x.replace(chr(34), chr(34)+chr(34))}"'
            for x in [r.name, r.action, r.direction, r.protocol, r.port, r.source, r.destination, r.notes]
        )
        for r in rules
    ]
    return "\n".join([header, *rows])


def to_iptables(rules: list[FirewallRule]) -> str:
    lines = ["# Generated by PortForge", ""]
    for r in rules:
        chain = "OUTPUT" if r.direction == "outbound" else "INPUT"
        target = {"allow": "ACCEPT", "reject": "REJECT"}.get(r.action, "DROP")
        proto = "tcp" if r.protocol.upper() in {"TCP", "TCP/UDP", "ANY"} else r.protocol.lower()
        port = r.port.replace("-", ":")
        src = f"-s {r.source}" if r.source.lower() not in {"any", "*"} else ""
        dst = f"-d {r.destination}" if r.destination.lower() not in {"any", "*"} else ""
        lines.append(f"# {r.name}")
        lines.append(f"iptables -A {chain} {src} {dst} -p {proto} --dport {port} -j {target}".replace("  ", " ").strip())
        lines.append("")
    return "\n".join(lines)


def to_asa(rules: list[FirewallRule]) -> str:
    lines = ["! Generated by PortForge", ""]
    for r in rules:
        action = "permit" if r.action == "allow" else "deny"
        proto = "ip" if r.protocol.upper() == "ANY" else r.protocol.lower().split("/")[0]
        src = r.source if r.source.lower() not in {"any", "*"} else "any"
        dst = r.destination if r.destination.lower() not in {"any", "*"} else "any"
        port = r.port.split(",")[0]
        lines.append(f"! {r.name}")
        lines.append(f"access-list PORTFORGE_ACL extended {action} {proto} {src} {dst} eq {port}")
        lines.append("")
    return "\n".join(lines)


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "PortForge"}


@app.get("/api/ports", response_model=list[PortEntry])
def list_ports(
    q: str | None = Query(None),
    risk: str | None = None,
    category: str | None = None,
):
    ports = load_ports()
    if not ports:
        raise HTTPException(503, "Port database not found. Sync frontend data/ports into backend/data.")
    query = (q or "").lower().strip()
    out = []
    for p in ports:
        if risk and p.get("risk") != risk:
            continue
        if category and category != "all" and p.get("category") != category:
            continue
        if query:
            blob = " ".join(
                [
                    str(p.get("port", "")),
                    p.get("service", ""),
                    p.get("note", ""),
                    p.get("guidance", ""),
                    " ".join(p.get("aliases") or []),
                    p.get("category", ""),
                    p.get("risk", ""),
                ]
            ).lower()
            if query not in blob:
                continue
        out.append(p)
    return out


@app.get("/api/ports/{port_number}")
def get_port(port_number: int):
    for p in load_ports():
        if p.get("port") == port_number:
            return p
    raise HTTPException(404, f"Port {port_number} not found")


@app.post("/api/conflicts", response_model=list[Conflict])
def conflicts(body: ConflictRequest):
    return detect_conflicts(body.rules)


@app.post("/api/export")
def export_rules(body: ExportRequest):
    if body.format == "markdown":
        content = to_markdown(body.rules, body.title)
    elif body.format == "csv":
        content = to_csv(body.rules)
    elif body.format == "iptables":
        content = to_iptables(body.rules)
    else:
        content = to_asa(body.rules)
    return {"format": body.format, "content": content}


@app.get("/api/suggest/{port_number}")
def suggest(port_number: int):
    port = next((p for p in load_ports() if p.get("port") == port_number), None)
    if not port:
        raise HTTPException(404, f"Port {port_number} not found")
    high = port["risk"] in {"critical", "high"}
    return {
        "name": f"{port['service']} {'restricted' if high else 'standard'}",
        "action": "allow",
        "direction": "inbound",
        "protocol": port["proto"] if port["proto"] != "TCP/UDP" else "TCP",
        "port": str(port["port"]),
        "source": "vpn-pool / jump-host" if high else "app-tier",
        "destination": f"{port['service'].lower()}-hosts" if high else "service-vip",
        "notes": f"Safe baseline: {port['guidance']}",
        "risk": port["risk"],
    }
