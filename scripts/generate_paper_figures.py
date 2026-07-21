#!/usr/bin/env python3
"""Generate SVG figures for the M-HIBE range-query paper draft.

The script intentionally uses only the Python standard library so it can run in
the Codex/WSL workspace without installing plotting packages.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from math import log10
from typing import Iterable
import html


OUT_DIR = Path("output/figures")


COLORS = {
    "prefix": "#4C78A8",
    "wkd": "#F58518",
    "zk_commit": "#54A24B",
    "zk_prover": "#B279A2",
    "serial": "#E45756",
    "parallel": "#2F80ED",
    "empty": "#72B7B2",
    "real": "#59A14F",
    "grid": "#9D755D",
    "muted": "#6B7280",
    "axis": "#374151",
    "light": "#E5E7EB",
    "text": "#111827",
    "bg": "#FFFFFF",
}


@dataclass(frozen=True)
class RunData:
    name: str
    prefix_ms: float
    wkd_ms: float
    zk_commit_ms: float
    zk_prover_ms: float
    client_empty_ms: float
    zk_verify_ms: float

    @property
    def engine_a_ms(self) -> float:
        return self.prefix_ms + self.wkd_ms

    @property
    def server_ms(self) -> float:
        return self.engine_a_ms + self.zk_commit_ms + self.zk_prover_ms

    @property
    def client_ms(self) -> float:
        return self.client_empty_ms + self.zk_verify_ms


SERIAL = RunData(
    name="Serial 3D",
    prefix_ms=8843.62,
    wkd_ms=68780.40,
    zk_commit_ms=21459.65,
    zk_prover_ms=1880.51,
    client_empty_ms=1645.4365,
    zk_verify_ms=2.45,
)

PARALLEL = RunData(
    name="Parallel 3D (20 workers)",
    prefix_ms=8963.33,
    wkd_ms=7354.54,
    zk_commit_ms=21703.57,
    zk_prover_ms=1935.65,
    client_empty_ms=157.6568,
    zk_verify_ms=2.50,
)

WORKER_CLIENT_MS = [
    (20, 157.6568),
    (100, 142.5111),
    (200, 142.5111),
]

COVER_DATA = {
    "Query canonical keys": 24,
    "Global empty parents": 20985,
    "Query-scoped empty keys": 4543,
}

POINT_DATA = {
    "Unique answer points": 2229,
    "Empty query points": 24051,
}

KEY_MATERIAL_KB = {
    "ZK proof": 1.20,
    "Query-range keys": 14.27,
    "Query-scoped empty keys": 1553.73,
    "Global parent keys touched": 1737.30,
}


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def tag(name: str, content: str = "", **attrs: object) -> str:
    attr = " ".join(f'{k.replace("_", "-")}="{esc(v)}"' for k, v in attrs.items())
    if content:
        return f"<{name} {attr}>{content}</{name}>"
    return f"<{name} {attr}/>"


def svg_doc(width: int, height: int, body: str) -> str:
    style = """
    <style>
      text { font-family: Inter, Segoe UI, Arial, sans-serif; fill: #111827; }
      .title { font-size: 24px; font-weight: 700; }
      .subtitle { font-size: 13px; fill: #6B7280; }
      .axis { stroke: #374151; stroke-width: 1; }
      .grid { stroke: #E5E7EB; stroke-width: 1; }
      .tick { font-size: 12px; fill: #6B7280; }
      .label { font-size: 13px; fill: #111827; }
      .value { font-size: 12px; font-weight: 600; fill: #111827; }
      .legend { font-size: 12px; fill: #374151; }
    </style>
    """
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img">\n'
        f'{style}\n'
        f'<rect width="100%" height="100%" fill="{COLORS["bg"]}"/>\n'
        f"{body}\n</svg>\n"
    )


def text(x: float, y: float, value: str, cls: str = "label", anchor: str = "start") -> str:
    return tag("text", esc(value), x=f"{x:.1f}", y=f"{y:.1f}", class_=cls, text_anchor=anchor)


def rect(x: float, y: float, w: float, h: float, fill: str, rx: int = 3) -> str:
    return tag("rect", x=f"{x:.1f}", y=f"{y:.1f}", width=f"{w:.1f}", height=f"{h:.1f}", fill=fill, rx=rx)


def line(x1: float, y1: float, x2: float, y2: float, cls: str = "axis") -> str:
    return tag("line", x1=f"{x1:.1f}", y1=f"{y1:.1f}", x2=f"{x2:.1f}", y2=f"{y2:.1f}", class_=cls)


def polyline(points: Iterable[tuple[float, float]], stroke: str, width: float = 2.5) -> str:
    pts = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
    return tag("polyline", points=pts, fill="none", stroke=stroke, stroke_width=width, stroke_linejoin="round")


def circle(cx: float, cy: float, r: float, fill: str) -> str:
    return tag("circle", cx=f"{cx:.1f}", cy=f"{cy:.1f}", r=f"{r:.1f}", fill=fill)


def legend(x: float, y: float, items: list[tuple[str, str]]) -> str:
    parts = []
    cursor = x
    for label, color in items:
        parts.append(rect(cursor, y - 10, 13, 13, color, rx=2))
        parts.append(text(cursor + 18, y + 1, label, "legend"))
        cursor += 18 + len(label) * 7.0 + 28
    return "\n".join(parts)


def fmt_s(ms: float) -> str:
    return f"{ms / 1000:.2f}s"


def fmt_ms(ms: float) -> str:
    return f"{ms:.1f}ms"


def draw_runtime_breakdown() -> str:
    width, height = 920, 560
    left, top, chart_w, chart_h = 105, 92, 610, 355
    max_s = 110
    runs = [SERIAL, PARALLEL]
    components = [
        ("Prefix extraction", "prefix", lambda r: r.prefix_ms / 1000),
        ("WKD-IBE delegation", "wkd", lambda r: r.wkd_ms / 1000),
        ("ZK commitment", "zk_commit", lambda r: r.zk_commit_ms / 1000),
        ("ZK prover", "zk_prover", lambda r: r.zk_prover_ms / 1000),
    ]
    parts = [
        text(48, 42, "Server Proving Time Breakdown", "title"),
        text(48, 65, "Parallelization reduces M-HIBE key delegation; ZK commitment becomes the dominant remaining cost.", "subtitle"),
        legend(48, 515, [(c[0], COLORS[c[1]]) for c in components]),
    ]
    for tick in range(0, max_s + 1, 20):
        y = top + chart_h - chart_h * tick / max_s
        parts.append(line(left, y, left + chart_w, y, "grid"))
        parts.append(text(left - 12, y + 4, str(tick), "tick", "end"))
    parts.append(line(left, top, left, top + chart_h))
    parts.append(line(left, top + chart_h, left + chart_w, top + chart_h))
    parts.append(text(38, top + chart_h / 2, "seconds", "tick", "middle"))

    bar_w = 104
    gap = 142
    for idx, run in enumerate(runs):
        x = left + 135 + idx * (bar_w + gap)
        y_cursor = top + chart_h
        for _, color_key, getter in components:
            val = getter(run)
            h = chart_h * val / max_s
            y_cursor -= h
            parts.append(rect(x, y_cursor, bar_w, h, COLORS[color_key]))
        parts.append(text(x + bar_w / 2, top + chart_h + 28, run.name, "label", "middle"))
        parts.append(text(x + bar_w / 2, y_cursor - 10, fmt_s(run.server_ms), "value", "middle"))

    reduction = SERIAL.server_ms / PARALLEL.server_ms
    parts.append(text(740, 148, f"{reduction:.2f}x", "title"))
    parts.append(text(740, 172, "lower server proving time", "subtitle"))
    parts.append(text(740, 218, f"{fmt_s(SERIAL.wkd_ms)} -> {fmt_s(PARALLEL.wkd_ms)}", "value"))
    parts.append(text(740, 240, "WKD-IBE delegation", "subtitle"))
    parts.append(text(740, 292, f"{fmt_s(PARALLEL.zk_commit_ms)}", "value"))
    parts.append(text(740, 314, "parallel run ZK commitment", "subtitle"))
    return svg_doc(width, height, "\n".join(parts))


def draw_engine_a_speedup() -> str:
    width, height = 860, 500
    left, top, chart_w, chart_h = 115, 92, 620, 300
    max_s = 75
    metrics = [
        ("Prefix extraction", SERIAL.prefix_ms / 1000, PARALLEL.prefix_ms / 1000),
        ("WKD-IBE delegation", SERIAL.wkd_ms / 1000, PARALLEL.wkd_ms / 1000),
        ("Engine A total", SERIAL.engine_a_ms / 1000, PARALLEL.engine_a_ms / 1000),
    ]
    parts = [
        text(48, 42, "Engine A: Where the Speedup Comes From", "title"),
        text(48, 65, "Only the cryptographic key-derivation portion shrinks substantially.", "subtitle"),
        legend(500, 64, [("Serial", COLORS["serial"]), ("Parallel", COLORS["parallel"])]),
    ]
    for tick in range(0, max_s + 1, 15):
        y = top + chart_h - chart_h * tick / max_s
        parts.append(line(left, y, left + chart_w, y, "grid"))
        parts.append(text(left - 12, y + 4, str(tick), "tick", "end"))
    parts.append(line(left, top, left, top + chart_h))
    parts.append(line(left, top + chart_h, left + chart_w, top + chart_h))
    parts.append(text(46, top + chart_h / 2, "seconds", "tick", "middle"))

    group_w = chart_w / len(metrics)
    bar_w = 48
    for i, (label, serial, parallel) in enumerate(metrics):
        cx = left + group_w * i + group_w / 2
        for j, (val, color) in enumerate([(serial, COLORS["serial"]), (parallel, COLORS["parallel"])]):
            h = chart_h * val / max_s
            x = cx - bar_w - 8 + j * (bar_w + 16)
            y = top + chart_h - h
            parts.append(rect(x, y, bar_w, h, color))
            parts.append(text(x + bar_w / 2, y - 8, f"{val:.1f}", "value", "middle"))
        parts.append(text(cx, top + chart_h + 28, label, "label", "middle"))

    parts.append(text(640, 165, f"{SERIAL.wkd_ms / PARALLEL.wkd_ms:.1f}x", "title"))
    parts.append(text(640, 189, "delegation speedup", "subtitle"))
    parts.append(text(640, 238, f"{SERIAL.engine_a_ms / PARALLEL.engine_a_ms:.1f}x", "title"))
    parts.append(text(640, 262, "Engine A speedup", "subtitle"))
    return svg_doc(width, height, "\n".join(parts))


def log_x(value: float, min_v: float, max_v: float, left: float, width: float) -> float:
    return left + width * (log10(value) - log10(min_v)) / (log10(max_v) - log10(min_v))


def draw_client_verification() -> str:
    width, height = 900, 470
    left, top, chart_w = 235, 105, 525
    min_v, max_v = 1.0, 2500.0
    rows = [
        ("Serial empty-key check", SERIAL.client_empty_ms, COLORS["serial"]),
        ("Parallel empty-key check", PARALLEL.client_empty_ms, COLORS["parallel"]),
        ("Serial ZK verifier", SERIAL.zk_verify_ms, COLORS["zk_commit"]),
        ("Parallel ZK verifier", PARALLEL.zk_verify_ms, COLORS["zk_prover"]),
    ]
    parts = [
        text(48, 42, "Client Verification Time", "title"),
        text(48, 65, "Log-scale view: empty-key checking dominates; the ZK verifier is only a few milliseconds.", "subtitle"),
    ]
    y0 = top
    for tick in [1, 10, 100, 1000]:
        x = log_x(tick, min_v, max_v, left, chart_w)
        parts.append(line(x, top - 28, x, top + 240, "grid"))
        parts.append(text(x, top + 270, f"{tick}", "tick", "middle"))
    parts.append(line(left, top + 240, left + chart_w, top + 240))
    parts.append(text(left + chart_w / 2, top + 305, "milliseconds (log scale)", "tick", "middle"))
    for i, (label, val, color) in enumerate(rows):
        y = y0 + i * 55
        x2 = log_x(val, min_v, max_v, left, chart_w)
        parts.append(text(left - 18, y + 16, label, "label", "end"))
        parts.append(rect(left, y, max(2, x2 - left), 24, color))
        parts.append(text(x2 + 8, y + 17, fmt_ms(val), "value"))
    return svg_doc(width, height, "\n".join(parts))


def draw_key_material() -> str:
    width, height = 900, 490
    left, top, chart_w = 245, 110, 520
    min_v, max_v = 1.0, 2500.0
    rows = list(KEY_MATERIAL_KB.items())
    colors = [COLORS["zk_prover"], COLORS["prefix"], COLORS["empty"], COLORS["wkd"]]
    parts = [
        text(48, 42, "Proof and Key Material Size", "title"),
        text(48, 65, "M-HIBE empty-key material dominates proof payload; ZK proof remains compact.", "subtitle"),
    ]
    for tick in [1, 10, 100, 1000]:
        x = log_x(tick, min_v, max_v, left, chart_w)
        parts.append(line(x, top - 28, x, top + 255, "grid"))
        parts.append(text(x, top + 285, f"{tick}", "tick", "middle"))
    parts.append(line(left, top + 255, left + chart_w, top + 255))
    parts.append(text(left + chart_w / 2, top + 320, "KB (log scale)", "tick", "middle"))
    for i, ((label, val), color) in enumerate(zip(rows, colors)):
        y = top + i * 58
        x2 = log_x(val, min_v, max_v, left, chart_w)
        parts.append(text(left - 18, y + 17, label, "label", "end"))
        parts.append(rect(left, y, max(2, x2 - left), 26, color))
        parts.append(text(x2 + 8, y + 18, f"{val:.2f} KB", "value"))
    return svg_doc(width, height, "\n".join(parts))


def draw_cover_composition() -> str:
    width, height = 940, 520
    left, top, chart_w = 265, 104, 530
    min_v, max_v = 10.0, 30000.0
    rows = [
        ("Query canonical keys", COVER_DATA["Query canonical keys"], COLORS["prefix"]),
        ("Global empty parent regions", COVER_DATA["Global empty parents"], COLORS["wkd"]),
        ("Query-scoped empty keys", COVER_DATA["Query-scoped empty keys"], COLORS["empty"]),
        ("Unique answer points", POINT_DATA["Unique answer points"], COLORS["real"]),
        ("Empty query points", POINT_DATA["Empty query points"], COLORS["grid"]),
    ]
    parts = [
        text(48, 42, "Cover Size and Query-Space Composition", "title"),
        text(48, 65, "The selected empty-key cover certifies the complement of the returned answer points.", "subtitle"),
    ]
    for tick in [10, 100, 1000, 10000]:
        x = log_x(tick, min_v, max_v, left, chart_w)
        parts.append(line(x, top - 28, x, top + 305, "grid"))
        parts.append(text(x, top + 335, f"{tick:,}", "tick", "middle"))
    parts.append(line(left, top + 305, left + chart_w, top + 305))
    parts.append(text(left + chart_w / 2, top + 370, "count (log scale)", "tick", "middle"))
    for i, (label, val, color) in enumerate(rows):
        y = top + i * 57
        x2 = log_x(float(val), min_v, max_v, left, chart_w)
        parts.append(text(left - 18, y + 17, label, "label", "end"))
        parts.append(rect(left, y, max(2, x2 - left), 26, color))
        parts.append(text(x2 + 8, y + 18, f"{val:,}", "value"))

    total = sum(POINT_DATA.values())
    parts.append(text(650, 442, f"Query grid: {total:,} points", "value"))
    parts.append(text(650, 465, f"Empty share: {POINT_DATA['Empty query points'] / total:.1%}", "subtitle"))
    return svg_doc(width, height, "\n".join(parts))


def draw_worker_sensitivity() -> str:
    width, height = 820, 460
    left, top, chart_w, chart_h = 105, 92, 600, 260
    min_x, max_x = 0, 220
    min_y, max_y = 135, 165
    parts = [
        text(48, 42, "Verifier Worker Sensitivity", "title"),
        text(48, 65, "Oversubscription slightly improves sampled client key checks, but does not materially change Engine A.", "subtitle"),
    ]
    for ytick in [140, 150, 160]:
        y = top + chart_h - chart_h * (ytick - min_y) / (max_y - min_y)
        parts.append(line(left, y, left + chart_w, y, "grid"))
        parts.append(text(left - 12, y + 4, str(ytick), "tick", "end"))
    for xtick in [20, 100, 200]:
        x = left + chart_w * (xtick - min_x) / (max_x - min_x)
        parts.append(line(x, top, x, top + chart_h, "grid"))
        parts.append(text(x, top + chart_h + 28, str(xtick), "tick", "middle"))
    parts.append(line(left, top, left, top + chart_h))
    parts.append(line(left, top + chart_h, left + chart_w, top + chart_h))
    parts.append(text(left + chart_w / 2, top + chart_h + 60, "M-HIBE workers", "tick", "middle"))
    parts.append(text(40, top + chart_h / 2, "ms", "tick", "middle"))

    pts = []
    for workers, ms in WORKER_CLIENT_MS:
        x = left + chart_w * (workers - min_x) / (max_x - min_x)
        y = top + chart_h - chart_h * (ms - min_y) / (max_y - min_y)
        pts.append((x, y))
    parts.append(polyline(pts, COLORS["parallel"], width=3.0))
    for workers, ms in WORKER_CLIENT_MS:
        x = left + chart_w * (workers - min_x) / (max_x - min_x)
        y = top + chart_h - chart_h * (ms - min_y) / (max_y - min_y)
        parts.append(circle(x, y, 5, COLORS["parallel"]))
        parts.append(text(x + 8, y - 8, f"{ms:.1f} ms", "value"))

    parts.append(text(575, 150, "Main result should use 20 workers", "value"))
    parts.append(text(575, 173, "to match logical CPU count.", "subtitle"))
    return svg_doc(width, height, "\n".join(parts))


def write(name: str, content: str) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / name
    path.write_text(content, encoding="utf-8")
    print(path)


def main() -> None:
    write("fig_runtime_breakdown.svg", draw_runtime_breakdown())
    write("fig_engine_a_speedup.svg", draw_engine_a_speedup())
    write("fig_client_verification.svg", draw_client_verification())
    write("fig_key_material.svg", draw_key_material())
    write("fig_cover_composition.svg", draw_cover_composition())
    write("fig_worker_sensitivity.svg", draw_worker_sensitivity())


if __name__ == "__main__":
    main()
