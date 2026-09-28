"""The network intent model.

An intent document describes *what the network should be*, never how to build
it. It is a typed graph:

* **nodes** are participants -- an endpoint, a service, a worker, a store, a
  gateway, or a model
* **edges** are data flows, each carrying a named payload under constraints

forge reads that graph and derives the code. The graph is the source of truth;
generated code is a pure function of it. That is the whole point of intent-based
design: you state the desired end condition and the system computes the
configuration that satisfies it, rather than you writing the configuration and
hoping it adds up to what you meant.

Example::

    {
      "schema": "forge.intent/v1",
      "name": "scan-billing",
      "objective": "Meter and bill cancer-scan analyses.",
      "rigor": "extreme",
      "network": {
        "nodes": [
          {"id": "intake", "kind": "endpoint", "generator": "drf_endpoint"},
          {"id": "ledger", "kind": "store", "generator": "python_module"}
        ],
        "edges": [
          {"from": "intake", "to": "ledger", "carries": "ScanCharge",
           "constraints": {"auth": "required", "idempotent": true}}
        ]
      }
    }
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .errors import IntentError
from .hashing import digest_object, hex_be

SCHEMA_INTENT = "forge.intent/v1"

NODE_KINDS = frozenset({"endpoint", "service", "worker", "store", "gateway", "model"})

# Edge constraints forge understands. Anything else is rejected rather than
# silently ignored -- a typo'd constraint that does nothing is worse than an
# error, because it looks like it is protecting you.
EDGE_CONSTRAINTS: dict[str, type | tuple[type, ...]] = {
    "auth": str,          # "none" | "required" | "service"
    "idempotent": bool,
    "max_bytes": int,
    "pii": bool,          # payload carries personal data
    "rate_limit": int,    # requests per minute, 0 = unlimited
    "retries": int,
    "timeout_ms": int,
}

AUTH_MODES = frozenset({"none", "required", "service"})

_ID_RE = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
_TYPE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,62}$")


@dataclass(frozen=True)
class Node:
    """A participant in the intended network."""

    id: str
    kind: str
    generator: str
    description: str = ""
    params: dict[str, Any] = field(default_factory=dict)

    def document(self) -> dict[str, Any]:
        return {
            "description": self.description,
            "generator": self.generator,
            "id": self.id,
            "kind": self.kind,
            "params": self.params,
        }


@dataclass(frozen=True)
class Edge:
    """A directed data flow between two nodes."""

    source: str
    target: str
    carries: str
    constraints: dict[str, Any] = field(default_factory=dict)

    def document(self) -> dict[str, Any]:
        return {
            "carries": self.carries,
            "constraints": self.constraints,
            "from": self.source,
            "to": self.target,
        }

    @property
    def label(self) -> str:
        return f"{self.source}->{self.target}"


@dataclass(frozen=True)
class Intent:
    """A validated intent document."""

    name: str
    objective: str
    nodes: tuple[Node, ...]
    edges: tuple[Edge, ...]
    rigor: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def document(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_INTENT,
            "metadata": self.metadata,
            "name": self.name,
            "network": {
                "edges": [edge.document() for edge in self.edges],
                "nodes": [node.document() for node in self.nodes],
            },
            "objective": self.objective,
            "rigor": self.rigor or "",
        }

    @property
    def digest(self) -> bytes:
        return digest_object(self.document())

    @property
    def digest_hex(self) -> str:
        return hex_be(self.digest)

    def node(self, node_id: str) -> Node:
        for node in self.nodes:
            if node.id == node_id:
                return node
        raise IntentError(f"no node named {node_id!r}")

    def inbound(self, node_id: str) -> list[Edge]:
        return sorted(
            (edge for edge in self.edges if edge.target == node_id),
            key=lambda e: (e.source, e.carries),
        )

    def outbound(self, node_id: str) -> list[Edge]:
        return sorted(
            (edge for edge in self.edges if edge.source == node_id),
            key=lambda e: (e.target, e.carries),
        )


def parse(raw: Any) -> tuple[Intent, list[str]]:
    """Validate ``raw`` into an :class:`Intent`, returning it with warnings.

    Hard structural problems raise :class:`IntentError`. Soft problems -- an
    isolated node, a PII flow without auth -- come back as warnings, which
    ``strict`` and ``extreme`` rigor promote to failures.
    """
    warnings: list[str] = []

    if not isinstance(raw, dict):
        raise IntentError(f"intent must be a JSON object, got {type(raw).__name__}")

    schema = raw.get("schema")
    if schema != SCHEMA_INTENT:
        raise IntentError(f"intent schema must be {SCHEMA_INTENT!r}, got {schema!r}")

    name = _require_str(raw, "name")
    if not _ID_RE.match(name.replace("-", "_")):
        raise IntentError(
            f"intent name {name!r} must be lowercase alphanumeric with _ or -, "
            "starting with a letter"
        )
    objective = _require_str(raw, "objective")

    rigor = raw.get("rigor")
    if rigor is not None and not isinstance(rigor, str):
        raise IntentError("intent 'rigor' must be a string if present")

    metadata = raw.get("metadata", {})
    if not isinstance(metadata, dict):
        raise IntentError("intent 'metadata' must be an object")

    network = raw.get("network")
    if not isinstance(network, dict):
        raise IntentError("intent must contain a 'network' object")

    raw_nodes = network.get("nodes")
    if not isinstance(raw_nodes, list) or not raw_nodes:
        raise IntentError("intent network must declare a non-empty 'nodes' array")

    nodes: list[Node] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(raw_nodes):
        node = _parse_node(item, index)
        if node.id in seen_ids:
            raise IntentError(f"duplicate node id {node.id!r}")
        seen_ids.add(node.id)
        nodes.append(node)

    raw_edges = network.get("edges", [])
    if not isinstance(raw_edges, list):
        raise IntentError("intent network 'edges' must be an array")

    edges: list[Edge] = []
    seen_edges: set[tuple[str, str, str]] = set()
    for index, item in enumerate(raw_edges):
        edge = _parse_edge(item, index, seen_ids)
        key = (edge.source, edge.target, edge.carries)
        if key in seen_edges:
            raise IntentError(
                f"duplicate edge {edge.label} carrying {edge.carries!r}"
            )
        seen_edges.add(key)
        edges.append(edge)

    # Deterministic ordering: the digest must not depend on authoring order.
    nodes.sort(key=lambda n: n.id)
    edges.sort(key=lambda e: (e.source, e.target, e.carries))

    warnings.extend(_semantic_warnings(nodes, edges))
    _reject_cycles(nodes, edges)

    intent = Intent(
        name=name,
        objective=objective,
        nodes=tuple(nodes),
        edges=tuple(edges),
        rigor=rigor,
        metadata=metadata,
    )
    return intent, warnings


def _parse_node(item: Any, index: int) -> Node:
    where = f"network.nodes[{index}]"
    if not isinstance(item, dict):
        raise IntentError(f"{where} must be an object")

    node_id = _require_str(item, "id", where)
    if not _ID_RE.match(node_id):
        raise IntentError(
            f"{where}.id {node_id!r} must be snake_case: a lowercase letter "
            "followed by lowercase letters, digits, or underscores"
        )

    kind = _require_str(item, "kind", where)
    if kind not in NODE_KINDS:
        raise IntentError(
            f"{where}.kind {kind!r} is not a known node kind; "
            f"expected one of: {', '.join(sorted(NODE_KINDS))}"
        )

    generator = item.get("generator")
    if generator is None:
        generator = _DEFAULT_GENERATOR_FOR_KIND[kind]
    if not isinstance(generator, str) or not generator:
        raise IntentError(f"{where}.generator must be a non-empty string")

    description = item.get("description", "")
    if not isinstance(description, str):
        raise IntentError(f"{where}.description must be a string")

    params = item.get("params", {})
    if not isinstance(params, dict):
        raise IntentError(f"{where}.params must be an object")

    return Node(
        id=node_id,
        kind=kind,
        generator=generator,
        description=description,
        params=params,
    )


_DEFAULT_GENERATOR_FOR_KIND = {
    "endpoint": "drf_endpoint",
    "service": "python_module",
    "worker": "python_module",
    "store": "python_module",
    "gateway": "python_module",
    "model": "python_module",
}


def _parse_edge(item: Any, index: int, node_ids: set[str]) -> Edge:
    where = f"network.edges[{index}]"
    if not isinstance(item, dict):
        raise IntentError(f"{where} must be an object")

    source = _require_str(item, "from", where)
    target = _require_str(item, "to", where)
    for role, value in (("from", source), ("to", target)):
        if value not in node_ids:
            raise IntentError(
                f"{where}.{role} references unknown node {value!r}; "
                f"declared nodes: {', '.join(sorted(node_ids))}"
            )
    if source == target:
        raise IntentError(f"{where} is a self-loop on node {source!r}")

    carries = _require_str(item, "carries", where)
    if not _TYPE_RE.match(carries):
        raise IntentError(
            f"{where}.carries {carries!r} must be a PascalCase type name"
        )

    constraints = item.get("constraints", {})
    if not isinstance(constraints, dict):
        raise IntentError(f"{where}.constraints must be an object")
    for key, value in constraints.items():
        if key not in EDGE_CONSTRAINTS:
            raise IntentError(
                f"{where}.constraints has unknown key {key!r}; "
                f"supported: {', '.join(sorted(EDGE_CONSTRAINTS))}"
            )
        expected = EDGE_CONSTRAINTS[key]
        # bool is a subclass of int; check it first so True is not a valid int.
        if expected is int and isinstance(value, bool):
            raise IntentError(f"{where}.constraints.{key} must be an integer, got a boolean")
        if not isinstance(value, expected):
            raise IntentError(
                f"{where}.constraints.{key} must be "
                f"{getattr(expected, '__name__', expected)}, got {type(value).__name__}"
            )
        if expected is int and value < 0:
            raise IntentError(f"{where}.constraints.{key} must be non-negative")
    auth = constraints.get("auth")
    if auth is not None and auth not in AUTH_MODES:
        raise IntentError(
            f"{where}.constraints.auth {auth!r} must be one of: {', '.join(sorted(AUTH_MODES))}"
        )

    return Edge(source=source, target=target, carries=carries, constraints=constraints)


def _semantic_warnings(nodes: list[Node], edges: list[Edge]) -> list[str]:
    """Checks that are suspicious rather than fatal."""
    warnings: list[str] = []
    connected = {edge.source for edge in edges} | {edge.target for edge in edges}

    for node in nodes:
        if len(nodes) > 1 and node.id not in connected:
            warnings.append(
                f"node {node.id!r} has no edges: it is isolated from the rest of the network"
            )
        if not node.description:
            warnings.append(f"node {node.id!r} has no description")

    for edge in edges:
        constraints = edge.constraints
        if constraints.get("pii") and constraints.get("auth", "none") == "none":
            warnings.append(
                f"edge {edge.label} carries PII ({edge.carries}) with auth=none; "
                "personal data should not flow over an unauthenticated link"
            )
        if constraints.get("retries", 0) > 0 and not constraints.get("idempotent", False):
            warnings.append(
                f"edge {edge.label} sets retries={constraints['retries']} but is not "
                "marked idempotent; retrying a non-idempotent call can duplicate effects"
            )
        if "max_bytes" in constraints and constraints["max_bytes"] == 0:
            warnings.append(f"edge {edge.label} sets max_bytes=0, which forbids any payload")

    for node in nodes:
        if node.kind == "store" and not any(edge.target == node.id for edge in edges):
            warnings.append(f"store {node.id!r} is never written to")

        # Origin nodes are entered from outside the graph, so no edge describes
        # the inbound call. If nothing anywhere demands auth, the system's front
        # door is open. Flag it rather than letting the fallback hide it.
        inbound = [edge for edge in edges if edge.target == node.id]
        outbound = [edge for edge in edges if edge.source == node.id]
        if node.kind == "endpoint" and not inbound:
            declared = node.params.get("auth")
            strongest = max(
                (str(edge.constraints.get("auth", "none")) for edge in outbound),
                key=lambda mode: {"none": 0, "service": 1, "required": 2}.get(mode, 0),
                default="none",
            )
            if declared not in AUTH_MODES and strongest == "none":
                warnings.append(
                    f"endpoint {node.id!r} is entered from outside the network and no edge "
                    "requires auth; set params.auth on the node, or auth on an outbound edge"
                )

    return sorted(set(warnings))


def _reject_cycles(nodes: list[Node], edges: list[Edge]) -> None:
    """The intent graph must be acyclic so a build order exists."""
    adjacency: dict[str, list[str]] = {node.id: [] for node in nodes}
    for edge in edges:
        adjacency[edge.source].append(edge.target)
    for key in adjacency:
        adjacency[key].sort()

    WHITE, GREY, BLACK = 0, 1, 2
    colour = {node.id: WHITE for node in nodes}
    stack: list[str] = []

    def visit(node_id: str) -> None:
        colour[node_id] = GREY
        stack.append(node_id)
        for neighbour in adjacency[node_id]:
            if colour[neighbour] == GREY:
                cycle = stack[stack.index(neighbour):] + [neighbour]
                raise IntentError(
                    "intent network contains a cycle: " + " -> ".join(cycle) +
                    "\n  An intent graph must be acyclic; a cycle has no build order."
                )
            if colour[neighbour] == WHITE:
                visit(neighbour)
        stack.pop()
        colour[node_id] = BLACK

    for node in sorted(nodes, key=lambda n: n.id):
        if colour[node.id] == WHITE:
            visit(node.id)


def _require_str(source: dict[str, Any], key: str, where: str = "intent") -> str:
    value = source.get(key)
    if not isinstance(value, str) or not value.strip():
        raise IntentError(f"{where}.{key} must be a non-empty string")
    return value


__all__ = [
    "SCHEMA_INTENT",
    "NODE_KINDS",
    "EDGE_CONSTRAINTS",
    "Node",
    "Edge",
    "Intent",
    "parse",
]
