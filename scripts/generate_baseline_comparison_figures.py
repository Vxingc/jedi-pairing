#!/usr/bin/env python3
"""Generate clean academic-style SVG baseline comparison figures.

The figures read `data/baseline_comparison.csv`. Empty cells are allowed; a
scheme with missing data is drawn as a light placeholder and labelled "n/a".
Once the PoneglyphDB row is filled, rerun this script and the placeholder will
be replaced by a normal bar.
"""

from __future__ import annotations

import csv
import html
from dataclasses import dataclass
from math import ceil, floor, log10
from pathlib import Path


DATA_PATH = Path("data/baseline_comparison.csv")
OUT_DIR = Path("output/figures")


@dataclass
class Row:
    scheme: str
    server_time_s: float | None
    client_verify_ms: float | None
    vo_size_kb: float | None


def parse_float(value: str) -> float | None:
    value = value.strip()
    return float(value) if value else None


def rows() -> list[Row]:
    with DATA_PATH.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return [
            Row(
                scheme=r["scheme"],
                server_time_s=parse_float(r["server_time_s"]),
                client_verify_ms=parse_float(r["client_verify_ms"]),
                vo_size_kb=parse_float(r["vo_size_kb"]),
            )
            for r in reader
        ]


def esc(x: object) -> str:
    return html.escape(str(x), quote=True)


def tag(name: str, content: str = "", **attrs: object) -> str:
    attr = " ".join(f'{k.replace("_", "-")}="{esc(v)}"' for k, v in attrs.items())
    return f"<{name} {attr}>{content}</{name}>" if content else f"<{name} {attr}/>"


def text(x: float, y: float, value: str, cls: str = "label", anchor: str = "middle") -> str:
    return tag("text", esc(value), x=f"{x:.1f}", y=f"{y:.1f}", class_=cls, text_anchor=anchor)


def line(x1: float, y1: float, x2: float, y2: float, cls: str = "axis") -> str:
    return tag("line", x1=f"{x1:.1f}", y1=f"{y1:.1f}", x2=f"{x2:.1f}", y2=f"{y2:.1f}", class_=cls)


def rect(x: float, y: float, w: float, h: float, fill: str, cls: str = "bar") -> str:
    return tag("rect", x=f"{x:.1f}", y=f"{y:.1f}", width=f"{w:.1f}", height=f"{h:.1f}", fill=fill, class_=cls)


def svg(width: int, height: int, body: str) -> str:
    defs = """
    <defs>
      <pattern id="hatch1" patternUnits="userSpaceOnUse" width="6" height="6" patternTransform="rotate(45)">
        <line x1="0" y1="0" x2="0" y2="6" stroke="#333" stroke-width="0.7"/>
      </pattern>
      <pattern id="hatch2" patternUnits="userSpaceOnUse" width="6" height="6" patternTransform="rotate(135)">
        <line x1="0" y1="0" x2="0" y2="6" stroke="#333" stroke-width="0.7"/>
      </pattern>
    </defs>
    """
    style = """
    <style>
      text { font-family: "Times New Roman", Times, serif; fill: #111; }
      .label { font-size: 13px; }
      .tick { font-size: 12px; }
      .axis-title { font-size: 15px; font-weight: 600; }
      .legend { font-size: 12px; }
      .value { font-size: 11px; fill: #333; }
      .axis { stroke: #111; stroke-width: 1.2; shape-rendering: crispEdges; }
      .grid { stroke: #d8d8d8; stroke-width: 0.7; stroke-dasharray: 2 4; }
      .bar { stroke: #111; stroke-width: 0.9; }
      .placeholder { stroke: #888; stroke-width: 0.9; stroke-dasharray: 3 3; }
    </style>
    """
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img">\n'
        f'<rect width="100%" height="100%" fill="#fff"/>\n{defs}\n{style}\n{body}\n</svg>\n'
    )


def log_ticks(values: list[float]) -> list[float]:
    lo = max(min(values) * 0.65, 1e-6)
    hi = max(values) * 1.55
    return [10.0**p for p in range(floor(log10(lo)), ceil(log10(hi)) + 1)]


def y_pos(v: float, lo: float, hi: float, top: float, h: float) -> float:
    return top + h - h * (log10(v) - log10(lo)) / (log10(hi) - log10(lo))


def tick_label(v: float) -> str:
    exp = int(round(log10(v)))
    if exp == 0:
        return "1"
    return f"10^{exp}"


def scheme_label(name: str) -> str:
    return {
        "Pure ZK-Accumulator": "Pure Acc.",
        "PoneglyphDB": "PoneglyphDB",
        "Ours M-HIBE+ZK": "Ours",
    }.get(name, name)


def fmt(v: float, unit: str) -> str:
    if v >= 1000:
        return f"{v:.0f}"
    if v >= 100:
        return f"{v:.0f}"
    if v >= 10:
        return f"{v:.1f}"
    return f"{v:.2f}"


def draw_metric(data: list[Row], attr: str, y_label: str, unit: str) -> str:
    width, height = 520, 360
    left, right, top, bottom = 64, 20, 28, 68
    plot_w = width - left - right
    plot_h = height - top - bottom

    vals = [getattr(r, attr) for r in data if getattr(r, attr) is not None and getattr(r, attr) > 0]
    if not vals:
        vals = [1.0]
    ticks = log_ticks(vals)
    lo, hi = min(ticks), max(ticks)

    palette = [
        ("#bdbdbd", None),
        ("#9ecae1", "hatch1"),
        ("#fdae6b", "hatch2"),
    ]

    parts: list[str] = []

    for t in ticks:
        y = y_pos(t, lo, hi, top, plot_h)
        parts.append(line(left, y, width - right, y, "grid"))
        parts.append(line(left - 4, y, left, y, "axis"))
        parts.append(text(left - 8, y + 4, tick_label(t), "tick", "end"))

    parts.append(line(left, top, left, top + plot_h))
    parts.append(line(left, top + plot_h, width - right, top + plot_h))

    group_w = plot_w / len(data)
    bar_w = min(58, group_w * 0.45)
    legend_items = []

    for i, row in enumerate(data):
        cx = left + group_w * i + group_w / 2
        fill, hatch = palette[i % len(palette)]
        value = getattr(row, attr)

        if value is None or value <= 0:
            parts.append(tag("rect", x=f"{cx - bar_w/2:.1f}", y=f"{top + plot_h - 14:.1f}", width=f"{bar_w:.1f}", height="14", fill="none", class_="placeholder"))
            parts.append(text(cx, top + plot_h - 20, "n/a", "value"))
        else:
            y = y_pos(float(value), lo, hi, top, plot_h)
            h = top + plot_h - y
            parts.append(rect(cx - bar_w / 2, y, bar_w, h, fill))
            if hatch:
                parts.append(rect(cx - bar_w / 2, y, bar_w, h, f"url(#{hatch})"))
            parts.append(text(cx, y - 5, fmt(float(value), unit), "value"))

        parts.append(text(cx, top + plot_h + 22, scheme_label(row.scheme), "tick"))
        legend_items.append((scheme_label(row.scheme), fill, hatch))

    parts.append(text(width / 2, height - 14, "Scheme", "axis-title"))
    parts.append(tag("text", esc(y_label), x="16", y=f"{top + plot_h/2:.1f}", class_="axis-title", text_anchor="middle", transform=f"rotate(-90 16 {top + plot_h/2:.1f})"))

    lx, ly = left + 8, top + 13
    for idx, (label, fill, hatch) in enumerate(legend_items):
        x = lx + idx * 130
        parts.append(rect(x, ly - 10, 17, 11, fill))
        if hatch:
            parts.append(rect(x, ly - 10, 17, 11, f"url(#{hatch})"))
        parts.append(text(x + 22, ly, label, "legend", "start"))

    return svg(width, height, "\n".join(parts))


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(path)


def main() -> None:
    data = rows()
    write(OUT_DIR / "baseline_server_time.svg", draw_metric(data, "server_time_s", "Server time (s)", "s"))
    write(OUT_DIR / "baseline_client_time.svg", draw_metric(data, "client_verify_ms", "Verify time (ms)", "ms"))
    write(OUT_DIR / "baseline_vo_size.svg", draw_metric(data, "vo_size_kb", "VO size (KB)", "KB"))


if __name__ == "__main__":
    main()
