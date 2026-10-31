#!/usr/bin/env python3
"""Generate the Excalidraw scenes for the README.

The scenes are written next to this file. Render them with the packaged CLI:

    excalidraw render docs/figures/datapath.excalidraw \
      --out docs/figures/datapath.png --scale 2 --max-width 3200 --padding 40

The script uses only the Python standard library. Colors follow the role
palette: blue ingress, purple engine runtime, orange policy and lookup state,
teal NAT and software PMD, green transmit and recycle, red drop and fail
closed, gray control plane.
"""

from __future__ import annotations

import json
from pathlib import Path

INK = "#1e1e1e"
MUTED = "#5c5f66"
BACKGROUND = "#ffffff"

# Role -> (stroke, fill). Fills stay pale so the hachure does not fight text.
BLUE = ("#1971c2", "#d0ebff")
PURPLE = ("#9c36b5", "#f3d9fa")
ORANGE = ("#f08c00", "#fff3bf")
TEAL = ("#0c8599", "#c5f6fa")
GREEN = ("#2f9e44", "#d3f9d8")
RED = ("#e03131", "#ffe3e3")
GRAY = ("#495057", "#f1f3f5")


def text_width(text: str, font_size: int) -> int:
    """Estimate the rendered width of the hand-drawn font."""
    widest = max(len(line) for line in text.split("\n"))
    return int(widest * font_size * 0.56) + 8


def text_height(text: str, font_size: int) -> int:
    return int(len(text.split("\n")) * font_size * 1.25)


class Scene:
    def __init__(self) -> None:
        self.elements: list[dict] = []
        self._next_seed = 1000

    def _seed(self) -> tuple[int, int]:
        self._next_seed += 1
        return self._next_seed, self._next_seed * 7 + 3

    def _base(self, element_id: str, kind: str, x: int, y: int, width: int, height: int) -> dict:
        seed, nonce = self._seed()
        return {
            "id": element_id,
            "type": kind,
            "x": x,
            "y": y,
            "width": width,
            "height": height,
            "angle": 0,
            "strokeColor": INK,
            "backgroundColor": "transparent",
            "fillStyle": "hachure",
            "strokeWidth": 2,
            "strokeStyle": "solid",
            "roughness": 2,
            "opacity": 100,
            "groupIds": [],
            "frameId": None,
            "roundness": None,
            "seed": seed,
            "version": 1,
            "versionNonce": nonce,
            "isDeleted": False,
            "boundElements": None,
            "updated": 1,
            "link": None,
            "locked": False,
        }

    def box(
        self,
        element_id: str,
        x: int,
        y: int,
        width: int,
        height: int,
        label: str | None = None,
        role: tuple[str, str] = GRAY,
        kind: str = "rectangle",
        font_size: int = 22,
    ) -> dict:
        stroke, fill = role
        text_id = f"{element_id}_label"
        element = self._base(element_id, kind, x, y, width, height)
        element.update(
            {
                "strokeColor": stroke,
                "backgroundColor": fill,
                "roundness": {"type": 3} if kind == "rectangle" else None,
                "boundElements": [{"type": "text", "id": text_id}] if label else [],
            }
        )
        self.elements.append(element)
        if label:
            self._bound_text(text_id, element_id, x, y, width, height, label, font_size)
        return element

    def _bound_text(
        self,
        text_id: str,
        container_id: str,
        x: int,
        y: int,
        width: int,
        height: int,
        label: str,
        font_size: int,
    ) -> None:
        element = self._base(text_id, "text", x, y, width - 20, text_height(label, font_size))
        element.update(
            {
                "strokeColor": INK,
                "strokeWidth": 2,
                "fontSize": font_size,
                "fontFamily": 1,
                "text": label,
                "textAlign": "center",
                "verticalAlign": "middle",
                "containerId": container_id,
                "originalText": label,
                "lineHeight": 1.25,
                "baseline": int(font_size * 0.32),
                "autoResize": True,
            }
        )
        self.elements.append(element)

    def note(
        self,
        element_id: str,
        x: int,
        y: int,
        text: str,
        font_size: int = 18,
        width: int | None = None,
    ) -> None:
        if width is None:
            width = text_width(text, font_size)
        element = self._base(element_id, "text", x, y, width, text_height(text, font_size))
        element.update(
            {
                "strokeColor": MUTED,
                "strokeWidth": 2,
                "fontSize": font_size,
                "fontFamily": 1,
                "text": text,
                "textAlign": "left",
                "verticalAlign": "top",
                "containerId": None,
                "originalText": text,
                "lineHeight": 1.25,
                "baseline": int(font_size * 0.32),
            }
        )
        self.elements.append(element)

    def title(self, text: str, subtitle: str | None = None) -> None:
        self.note("title", 40, 40, text, font_size=32)
        if subtitle:
            self.note("subtitle", 40, 86, subtitle, font_size=18)

    def arrow(
        self,
        element_id: str,
        start: tuple[int, int],
        end: tuple[int, int],
        label: str | None = None,
        label_at: tuple[int, int] | None = None,
        color: str = MUTED,
        dashed: bool = False,
    ) -> None:
        x, y = start
        dx, dy = end[0] - x, end[1] - y
        element = self._base(element_id, "arrow", x, y, abs(dx), abs(dy))
        element.update(
            {
                "strokeColor": color,
                "roundness": {"type": 2},
                "strokeStyle": "dashed" if dashed else "solid",
                "points": [[0, 0], [dx, dy]],
                "lastCommittedPoint": None,
                "startBinding": None,
                "endBinding": None,
                "startArrowhead": None,
                "endArrowhead": "arrow",
            }
        )
        self.elements.append(element)
        if label and label_at:
            width = text_width(label, 18)
            self.note(f"{element_id}_label", label_at[0] - width // 2, label_at[1], label)

    def write(self, path: Path) -> None:
        scene = {
            "type": "excalidraw",
            "version": 2,
            "source": "https://excalidraw.com",
            "elements": self.elements,
            "appState": {"viewBackgroundColor": BACKGROUND, "gridSize": None},
            "files": {},
        }
        path.write_text(json.dumps(scene, indent=2) + "\n", encoding="utf-8")


def datapath() -> Scene:
    scene = Scene()
    scene.title(
        "One polling thread owns every frame from RX to TX",
        "packet-engine dataplane: one selected backend, one loop",
    )

    # Row 1: ingress, batch receive, parse, policy lookup, decision.
    scene.box("afxdp", 60, 165, 230, 90, "AF_XDP UMEM\nqueue 0", BLUE)
    scene.box("dpdk", 60, 295, 230, 90, "DPDK ethdev\nqueue 0", TEAL)
    scene.box("recv", 370, 210, 220, 110, "recv_batch\nup to 64", PURPLE)
    scene.box("parse", 650, 210, 220, 110, "parse_packet\nzero-copy views", PURPLE)
    scene.box("lookup", 930, 210, 220, 110, "rule lookup\nexact, then LPM", ORANGE)
    scene.box("action", 1210, 210, 220, 110, "action", ORANGE)

    # Row 2: NAT, transmit, ownership return.
    scene.box("nat", 1210, 435, 220, 110, "NAT rewrite\nconntrack", TEAL)
    scene.box("send", 930, 435, 220, 110, "send_batch\naccepted count", PURPLE)
    scene.box("transmit", 650, 435, 220, 110, "accepted\ntransmit", GREEN)
    scene.box("drop", 650, 655, 220, 110, "rejected\nrelease frame", RED)
    scene.box("fill", 370, 435, 220, 110, "AF_XDP FILL\nfree frames", GREEN)

    scene.arrow("a_recv", (290, 210), (370, 250), "frames", (330, 195))
    scene.arrow("b_recv", (290, 340), (370, 290), "mbufs", (330, 330))
    scene.arrow("recv_parse", (590, 265), (650, 265), "batch", (620, 172))
    scene.arrow("parse_lookup", (870, 265), (930, 265), "IPv4 only", (900, 172))
    scene.arrow("lookup_action", (1150, 265), (1210, 265), "match", (1180, 172))

    scene.arrow("action_nat", (1320, 340), (1320, 435), "FORWARD", (1370, 372))
    scene.arrow("action_send", (1225, 290), (1040, 435), "ALLOW", (1090, 365))
    scene.arrow("nat_send", (1210, 490), (1150, 490), "rewritten", (1180, 398))
    scene.arrow("send_transmit", (930, 490), (870, 490), "accepted", (900, 398))
    scene.arrow("transmit_fill", (650, 490), (590, 490), "TX completion", (620, 398))
    scene.arrow("send_drop", (1040, 545), (830, 655), "rejected", (930, 590))
    scene.arrow("drop_fill", (650, 710), (480, 545), "drop recycle", (555, 630))
    scene.arrow("fill_recv", (480, 435), (480, 320), "refill", (515, 366))

    scene.note(
        "note-source",
        60,
        790,
        "AF_XDP returns frames through FILL. DPDK releases accepted mbufs to its mempool.",
    )
    scene.note(
        "note-owner",
        60,
        830,
        "A rejected frame stays application-owned until the recycle call.",
    )
    scene.note(
        "note-nat",
        1210,
        585,
        "NAT picks a backend,\nallocates a port.",
    )
    return scene


def forwarding() -> Scene:
    scene = Scene()
    scene.title(
        "A FORWARD rule fails closed until every NAT input resolves",
        "IPv4 L4 NAT with --vip: one missing input returns the frame",
    )

    scene.box("start", 60, 210, 230, 110, "FORWARD rule\nmatched", ORANGE)
    scene.box("nat_ok", 350, 210, 230, 110, "NAT eligible?", ORANGE)
    scene.box("backend", 640, 210, 230, 110, "backend found?", ORANGE)
    scene.box("mac", 930, 210, 230, 110, "next-hop MAC?", ORANGE)
    scene.box("rewrite", 1220, 210, 230, 110, "rewrite L3/L4\nincremental csum", TEAL)

    scene.box("drop_nat", 350, 445, 230, 100, "drop\nno NAT path", RED)
    scene.box("drop_backend", 640, 445, 230, 100, "drop\nno backend", RED)
    scene.box("drop_mac", 930, 445, 230, 100, "drop\nno MAC", RED)
    scene.box("tx", 1220, 445, 230, 100, "TX to backend", GREEN)

    scene.arrow("start_nat", (290, 265), (350, 265), "match", (320, 232))
    scene.arrow("nat_backend", (580, 265), (640, 265), "yes", (598, 232))
    scene.arrow("backend_mac", (870, 265), (930, 265), "yes", (888, 232))
    scene.arrow("mac_rewrite", (1160, 265), (1220, 265), "yes", (1178, 232))

    scene.arrow("nat_drop", (465, 320), (465, 445), "no", (440, 378))
    scene.arrow("backend_drop", (755, 320), (755, 445), "no", (730, 378))
    scene.arrow("mac_drop", (1045, 320), (1045, 445), "no", (1020, 378))
    scene.arrow("rewrite_tx", (1335, 320), (1335, 445), "rewritten", (1385, 368))

    scene.note(
        "note-checks",
        40,
        120,
        "NAT needs IPv4, TCP or UDP, and --vip. A backend needs a pin or Ketama hit, plus a MAC.",
    )
    scene.note(
        "note-port",
        1220,
        565,
        "The rewrite allocates\na port and binds\nconntrack.",
    )
    scene.note(
        "note-return",
        60,
        640,
        "Return traffic matches the swapped conntrack tuple before policy lookup.",
    )
    scene.note(
        "note-owner",
        60,
        680,
        "A miss leaves the frame on the recycle path, never on the wire.",
    )
    return scene


def control() -> Scene:
    scene = Scene()
    scene.title(
        "Control updates publish immutable snapshots",
        "the polling thread takes one acquire load per batch",
    )

    scene.note(
        "note-get",
        40,
        118,
        "GET /health, /rules, and /backends read the active snapshot.",
    )

    scene.box("operator", 60, 260, 200, 90, "operator\ncurl", GRAY)
    scene.box("api", 310, 255, 240, 100, "control API\nAF_UNIX socket", GRAY)
    scene.box("rules_in", 610, 120, 220, 100, "PUT /rules\nparse + validate", ORANGE)
    scene.box("backends_in", 610, 380, 220, 100, "PUT /backends\nvalidate set", ORANGE)
    scene.box("rules_snap", 900, 120, 220, 100, "new RuleTable\nimmutable", ORANGE)
    scene.box("ring_snap", 900, 380, 220, 100, "new Ketama ring\nimmutable", ORANGE)
    scene.box("publish", 1200, 250, 230, 110, "atomic publish\nshared_ptr", PURPLE)
    scene.box("dataplane", 1200, 470, 230, 110, "dataplane thread\none acquire", PURPLE)
    scene.box("prober", 910, 650, 230, 100, "health prober\nTCP every 5 s", TEAL)

    scene.arrow("operator_api", (260, 305), (310, 305), "HTTP", (285, 235))
    scene.arrow("api_rules", (470, 255), (610, 170), "rules", (535, 196))
    scene.arrow("api_backends", (470, 355), (610, 430), "backends", (535, 412))
    scene.arrow("rules_table", (830, 170), (900, 170), "build", (865, 140))
    scene.arrow("backends_ring", (830, 430), (900, 430), "rebuild", (865, 350))
    scene.arrow("table_publish", (1120, 170), (1200, 290), "rules", (1170, 225))
    scene.arrow("ring_publish", (1120, 430), (1200, 320), "ring", (1170, 390))
    scene.arrow("publish_dataplane", (1315, 360), (1315, 470), "publish", (1350, 405))
    scene.arrow("prober_ring", (1025, 650), (1025, 480), "state change", (952, 560))

    scene.note(
        "note-state",
        60,
        620,
        "Conntrack and flow state stay on the dataplane.\nA rules swap leaves them intact.",
    )
    scene.note(
        "note-metrics",
        60,
        720,
        "Metrics leave through a separate aggregator and TCP :9090.",
    )
    return scene


def main() -> None:
    directory = Path(__file__).resolve().parent
    datapath().write(directory / "datapath.excalidraw")
    forwarding().write(directory / "forwarding.excalidraw")
    control().write(directory / "control-plane.excalidraw")


if __name__ == "__main__":
    main()
