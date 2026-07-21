#!/usr/bin/env python3
"""Plot best-parallel vs PoneglyphDB vs ZK-acc for 2D and 3D.

The plotted parallel point uses the best observed value per metric across the
parallel worker sweep, as requested.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


FIGSIZE_SINGLE = (3.45, 2.05)

SCHEME_ORDER = ["Best Parallel", "PoneglyphDB", "ZK-acc"]
SCHEME_LABELS = {
    "Best Parallel": "Best Parallel",
    "PoneglyphDB": "PoneglyphDB",
    "ZK-acc": "ZK-acc",
}
SCHEME_COLORS = {
    "Best Parallel": "#2a9d8f",
    "PoneglyphDB": "#e76f51",
    "ZK-acc": "#4f6aa3",
}
SCHEME_HATCHES = {
    "Best Parallel": "",
    "PoneglyphDB": "//",
    "ZK-acc": "\\\\",
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
    parser = argparse.ArgumentParser(description="Plot best-parallel comparison figures")
    parser.add_argument("--data", default="data/experiment_best_parallel_comparison.csv")
    parser.add_argument("--out-dir", default="paper_results")
    return parser.parse_args()


def setup_axes(ax: plt.Axes, xlabel: str, ylabel: str) -> None:
    ax.set_xlabel(xlabel, labelpad=1.5)
    ax.set_ylabel(ylabel, labelpad=1.5)
    ax.grid(axis="y", alpha=0.25)
    ax.tick_params(axis="both", length=2.4, width=0.7, pad=1.5)
    for spine in ax.spines.values():
        spine.set_linewidth(0.7)


def write_figure(fig: plt.Figure, out_path: Path) -> None:
    fig.tight_layout(pad=0.12, w_pad=0.28)
    fig.savefig(out_path, bbox_inches="tight")
    fig.savefig(out_path.with_suffix(".png"), dpi=320, bbox_inches="tight")
    plt.close(fig)
    print(f"[best-parallel-plots] wrote {out_path}")


def read_data(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    for col in ["setup_s", "prove_s", "verify_ms"]:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    df["estimated"] = df["estimated"].astype(str).str.lower().isin(["true", "1", "yes"])
    order = {name: idx for idx, name in enumerate(SCHEME_ORDER)}
    df["_order"] = df["scheme"].map(order)
    return df.sort_values(["dimension", "_order"]).reset_index(drop=True)


def plot_metric(df: pd.DataFrame, dimension: str, metric: str, ylabel: str, out_path: Path) -> None:
    sub = df[df["dimension"] == dimension].copy()
    fig, ax = plt.subplots(figsize=FIGSIZE_SINGLE)
    x = list(range(len(sub)))
    values = list(sub[metric])
    finite = [v for v in values if pd.notna(v)]
    ymin = 0 if not finite else 0
    ymax = max(finite) * 1.18 if finite else 1.0
    for i, row in enumerate(sub.itertuples(index=False)):
        scheme = row.scheme
        value = getattr(row, metric)
        color = SCHEME_COLORS[scheme]
        hatch = SCHEME_HATCHES[scheme]
        if pd.isna(value):
            ax.bar(i, ymax * 0.02, width=0.58, color="white", edgecolor="#888", linewidth=0.55, hatch="..")
            ax.text(i, ymax * 0.05, "n/a", ha="center", va="bottom", fontsize=5.0, color="#555")
        else:
            ax.bar(i, value, width=0.58, color=color, edgecolor="black", linewidth=0.55, hatch=hatch)
            if row.estimated:
                ax.text(i, value * 1.03, "est.", ha="center", va="bottom", fontsize=4.9)
    ax.set_xticks(x)
    ax.set_xticklabels([SCHEME_LABELS[s] for s in sub["scheme"]], rotation=0, ha="center")
    ax.set_ylim(ymin, ymax)
    setup_axes(ax, "", ylabel)
    write_figure(fig, out_path)


def main() -> None:
    args = parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    df = read_data(Path(args.data))
    metrics = [
        ("setup_s", "Global setup (s)", "setup"),
        ("prove_s", "Prove (s)", "prove"),
        ("verify_ms", "Verify (ms)", "verify"),
    ]
    for dimension in ["2D", "3D"]:
        for metric, ylabel, suffix in metrics:
            plot_metric(df, dimension, metric, ylabel, out_dir / f"best_parallel_{dimension.lower()}_{suffix}.pdf")


if __name__ == "__main__":
    main()
