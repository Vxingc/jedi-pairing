#!/usr/bin/env python3
"""Generate paper figures from `实验结果.pdf` extracted data.

All axes are linear/evenly spaced as requested.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


FIGSIZE_SINGLE = (3.45, 2.05)
FIGSIZE_LINE = (3.45, 2.05)

SCHEME_ORDER = ["Our Scheme", "PoneglyphDB", "ZK-acc"]
SCHEME_COLORS = {
    "Our Scheme": "#2a9d8f",
    "PoneglyphDB": "#e76f51",
    "ZK-acc": "#4f6aa3",
}
SCHEME_HATCHES = {
    "Our Scheme": "",
    "PoneglyphDB": "//",
    "ZK-acc": "\\\\",
}

LINE_COLOR = "#2a9d8f"
TOTAL_COLOR = "#4f6aa3"
CLIENT_COLOR = "#e76f51"


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
    parser = argparse.ArgumentParser(description="Plot experiment figures extracted from PDF")
    parser.add_argument("--scheme-data", default="data/experiment_scheme_comparison.csv")
    parser.add_argument("--parallel-data", default="data/experiment_parallel_workers.csv")
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
    print(f"[experiment-plots] wrote {out_path}")


def read_scheme_data(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    for col in ["setup_s", "prove_s", "verify_ms"]:
        df[col] = pd.to_numeric(df[col], errors="raise")
    order = {name: idx for idx, name in enumerate(SCHEME_ORDER)}
    df["_order"] = df["scheme"].map(order)
    return df.sort_values(["dimension", "_order"]).reset_index(drop=True)


def read_parallel_data(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    for col in ["workers", "engine_a_ms", "total_server_ms", "total_client_ms", "wkd_delegation_ms", "client_empty_check_ms"]:
        df[col] = pd.to_numeric(df[col], errors="raise")
    return df.sort_values(["dimension", "workers"]).reset_index(drop=True)


def plot_scheme_metric(df: pd.DataFrame, dimension: str, metric: str, ylabel: str, out_path: Path) -> None:
    sub = df[df["dimension"] == dimension].copy()
    fig, ax = plt.subplots(figsize=FIGSIZE_SINGLE)
    x = list(range(len(sub)))
    for i, (_, row) in enumerate(sub.iterrows()):
        scheme = row["scheme"]
        ax.bar(
            i,
            row[metric],
            width=0.58,
            color=SCHEME_COLORS[scheme],
            edgecolor="black",
            linewidth=0.55,
            hatch=SCHEME_HATCHES[scheme],
        )
    ax.set_xticks(x)
    ax.set_xticklabels(list(sub["scheme"]), rotation=0, ha="center")
    ax.set_ylim(0, float(sub[metric].max()) * 1.18)
    setup_axes(ax, "", ylabel)
    write_figure(fig, out_path)


def plot_parallel_metric(df: pd.DataFrame, dimension: str, metric: str, ylabel: str, out_path: Path, color: str) -> None:
    sub = df[df["dimension"] == dimension].copy()
    fig, ax = plt.subplots(figsize=FIGSIZE_LINE)
    x_labels = list(sub["label"].astype(str))
    x = list(range(len(sub)))
    ax.plot(x, sub[metric], marker="o", markersize=2.4, linewidth=1.2, color=color)
    ax.set_xticks(x)
    ax.set_xticklabels(x_labels, rotation=0)
    ax.set_ylim(0, float(sub[metric].max()) * 1.18)
    setup_axes(ax, "Workers", ylabel)
    write_figure(fig, out_path)


def main() -> None:
    args = parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    scheme_df = read_scheme_data(Path(args.scheme_data))
    parallel_df = read_parallel_data(Path(args.parallel_data))

    scheme_metrics = [
        ("setup_s", "Setup (s)", "setup"),
        ("prove_s", "Prove (s)", "prove"),
        ("verify_ms", "Verify (ms)", "verify"),
    ]
    for dimension in ["2D", "3D"]:
        for metric, ylabel, suffix in scheme_metrics:
            plot_scheme_metric(
                scheme_df,
                dimension,
                metric,
                ylabel,
                out_dir / f"compare_{dimension.lower()}_{suffix}.pdf",
            )

    parallel_metrics = [
        ("engine_a_ms", "Engine A (ms)", "engine_a", LINE_COLOR),
        ("total_server_ms", "Server prove (ms)", "server", TOTAL_COLOR),
        ("total_client_ms", "Client verify (ms)", "client", CLIENT_COLOR),
    ]
    for dimension in ["2D", "3D"]:
        for metric, ylabel, suffix, color in parallel_metrics:
            plot_parallel_metric(
                parallel_df,
                dimension,
                metric,
                ylabel,
                out_dir / f"parallel_{dimension.lower()}_{suffix}.pdf",
                color,
            )


if __name__ == "__main__":
    main()
