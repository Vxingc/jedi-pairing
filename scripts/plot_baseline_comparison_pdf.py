#!/usr/bin/env python3
"""Plot paper-ready baseline comparison figures.

This script follows the plotting style of
`E:/storage-simulator/paper_result_extract_and_plot.py`: compact single-column
figures, small fonts, PDF font embedding, light grids, and PDF+PNG outputs.

Input CSV schema:
    scheme,server_time_s,client_verify_ms,vo_size_kb,notes

Empty metric cells are allowed; they are annotated as "n/a" in the plot.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


FIGSIZE_SINGLE = (3.45, 2.05)
FIGSIZE_PAIR = (3.45, 1.35)

SCHEME_ORDER = ["Pure ZK-Accumulator", "PoneglyphDB", "Ours M-HIBE+ZK"]
SCHEME_LABELS = {
    "Pure ZK-Accumulator": "Accumulator",
    "PoneglyphDB": "PoneglyphDB",
    "Ours M-HIBE+ZK": "Ours",
}
SCHEME_COLORS = {
    "Pure ZK-Accumulator": "#4f6aa3",
    "PoneglyphDB": "#e76f51",
    "Ours M-HIBE+ZK": "#2a9d8f",
}
SCHEME_HATCHES = {
    "Pure ZK-Accumulator": "",
    "PoneglyphDB": "//",
    "Ours M-HIBE+ZK": "\\\\",
}


plt.rcParams.update(
    {
        "font.size": 6.7,
        "axes.titlesize": 6.9,
        "axes.labelsize": 6.6,
        "xtick.labelsize": 5.8,
        "ytick.labelsize": 5.8,
        "legend.fontsize": 5.5,
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
    }
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Plot baseline comparison figures for the M-HIBE paper")
    parser.add_argument("--data", default="data/baseline_comparison.csv", help="baseline comparison CSV")
    parser.add_argument("--out-dir", default="paper_results", help="output directory for PDFs and PNG previews")
    return parser.parse_args()


def read_data(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    for col in ["server_time_s", "client_verify_ms", "vo_size_kb"]:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    order = {name: idx for idx, name in enumerate(SCHEME_ORDER)}
    df["_order"] = df["scheme"].map(order).fillna(len(SCHEME_ORDER))
    return df.sort_values("_order").reset_index(drop=True)


def setup_axes(ax: plt.Axes, xlabel: str, ylabel: str, logy: bool = True) -> None:
    ax.set_xlabel(xlabel, labelpad=1.5)
    ax.set_ylabel(ylabel, labelpad=1.5)
    if logy:
        ax.set_yscale("log")
    ax.grid(axis="y", alpha=0.25)
    ax.tick_params(axis="both", length=2.4, width=0.7, pad=1.5)
    for spine in ax.spines.values():
        spine.set_linewidth(0.7)


def write_figure(fig: plt.Figure, out_path: Path) -> None:
    fig.tight_layout(pad=0.12, w_pad=0.28)
    fig.savefig(out_path, bbox_inches="tight")
    fig.savefig(out_path.with_suffix(".png"), dpi=320, bbox_inches="tight")
    plt.close(fig)
    print(f"[baseline-plots] wrote {out_path}")


def metric_limits(values: pd.Series) -> tuple[float, float]:
    clean = values.dropna()
    if clean.empty:
        return 1.0, 10.0
    lo = max(clean.min() * 0.55, 1e-3)
    hi = clean.max() * 1.85
    if lo == hi:
        hi = lo * 10
    return lo, hi


def draw_bars(ax: plt.Axes, df: pd.DataFrame, metric: str, ylabel: str) -> None:
    labels = [SCHEME_LABELS.get(s, s) for s in df["scheme"]]
    x = list(range(len(df)))
    y = df[metric]
    ymin, ymax = metric_limits(y)

    for idx, row in df.iterrows():
        scheme = row["scheme"]
        value = row[metric]
        color = SCHEME_COLORS.get(scheme, "#7a7a7a")
        hatch = SCHEME_HATCHES.get(scheme, "")
        if pd.isna(value):
            ax.bar(idx, ymin * 1.25, color="white", edgecolor="#888888", linewidth=0.7, hatch="..")
            ax.text(idx, ymin * 1.55, "n/a", ha="center", va="bottom", fontsize=5.2, color="#555555")
        else:
            ax.bar(idx, value, color=color, edgecolor="black", linewidth=0.55, hatch=hatch)

    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=15, ha="right")
    ax.set_ylim(ymin, ymax)
    setup_axes(ax, "", ylabel, logy=True)


def plot_time_pair(df: pd.DataFrame, out_path: Path) -> None:
    fig, axes = plt.subplots(1, 2, figsize=FIGSIZE_PAIR)
    draw_bars(axes[0], df, "server_time_s", "Server (s)")
    draw_bars(axes[1], df, "client_verify_ms", "Verify (ms)")
    write_figure(fig, out_path)


def plot_vo_size(df: pd.DataFrame, out_path: Path) -> None:
    fig, ax = plt.subplots(figsize=FIGSIZE_SINGLE)
    draw_bars(ax, df, "vo_size_kb", "VO size (KB)")
    write_figure(fig, out_path)


def plot_all_metrics(df: pd.DataFrame, out_path: Path) -> None:
    fig, axes = plt.subplots(1, 3, figsize=(5.1, 1.35))
    draw_bars(axes[0], df, "server_time_s", "Server (s)")
    draw_bars(axes[1], df, "client_verify_ms", "Verify (ms)")
    draw_bars(axes[2], df, "vo_size_kb", "VO (KB)")
    write_figure(fig, out_path)


def main() -> None:
    args = parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    df = read_data(Path(args.data))

    plot_time_pair(df, out_dir / "baseline_time_comparison.pdf")
    plot_vo_size(df, out_dir / "baseline_vo_size.pdf")
    plot_all_metrics(df, out_dir / "baseline_all_metrics.pdf")


if __name__ == "__main__":
    main()
