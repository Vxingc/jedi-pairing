#!/usr/bin/env python3
"""Plot 2D/3D scheme comparison figures from manually extracted table data.

Style follows `paper_result_extract_and_plot.py`: compact PDF figures,
matplotlib/pandas, small fonts, light grids, and PNG previews.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


FIGSIZE_PAIR = (3.45, 1.52)
FIGSIZE_SINGLE = (3.45, 1.55)
FIGSIZE_DIM_SUMMARY = (3.45, 2.55)

SCHEMES = ["My Proposed", "PoneglyphDB", "ZK-acc"]
LABELS = {
    "My Proposed": "Ours",
    "PoneglyphDB": "PoneglyphDB",
    "ZK-acc": "ZK-acc",
}
COLORS = {
    "My Proposed": "#2a9d8f",
    "PoneglyphDB": "#e76f51",
    "ZK-acc": "#4f6aa3",
}
HATCHES = {
    "My Proposed": "",
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
        "legend.fontsize": 5.3,
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
    }
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Plot 2D/3D scheme comparison figures")
    parser.add_argument("--data", default="data/scheme_results_2d3d.csv", help="input CSV")
    parser.add_argument("--out-dir", default="paper_results", help="output directory")
    return parser.parse_args()


def read_data(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    numeric_cols = [
        "setup_s",
        "digest_s",
        "correct_prove_s",
        "complete_prove_s",
        "total_prove_incl_digest_s",
        "total_prove_excl_digest_s",
        "verify_ms",
    ]
    for col in numeric_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    df["estimated"] = df["estimated"].astype(str).str.lower().isin(["true", "1", "yes"])
    return df


def setup_axes(ax: plt.Axes, xlabel: str, ylabel: str, *, logy: bool = True) -> None:
    ax.set_xlabel(xlabel, labelpad=1.4)
    ax.set_ylabel(ylabel, labelpad=1.4)
    if logy:
        ax.set_yscale("log")
    ax.grid(axis="y", alpha=0.25)
    ax.tick_params(axis="both", length=2.4, width=0.7, pad=1.4)
    for spine in ax.spines.values():
        spine.set_linewidth(0.7)


def write_figure(fig: plt.Figure, out_path: Path) -> None:
    fig.tight_layout(pad=0.12, w_pad=0.25)
    fig.savefig(out_path, bbox_inches="tight")
    fig.savefig(out_path.with_suffix(".png"), dpi=320, bbox_inches="tight")
    plt.close(fig)
    print(f"[scheme-plots] wrote {out_path}")


def draw_grouped_bars(
    ax: plt.Axes,
    df: pd.DataFrame,
    metric: str,
    ylabel: str,
    *,
    annotate_est: bool = True,
    logy: bool = True,
) -> None:
    dims = ["2D", "3D"]
    x_centers = list(range(len(dims)))
    width = 0.22
    offsets = {
        "My Proposed": -width,
        "PoneglyphDB": 0.0,
        "ZK-acc": width,
    }
    all_values = []

    for scheme in SCHEMES:
        values = []
        est_flags = []
        for dim in dims:
            row = df[(df["dimension"] == dim) & (df["scheme"] == scheme)]
            if row.empty:
                values.append(float("nan"))
                est_flags.append(False)
            else:
                values.append(float(row.iloc[0][metric]) if pd.notna(row.iloc[0][metric]) else float("nan"))
                est_flags.append(bool(row.iloc[0]["estimated"]))
        all_values.extend([v for v in values if pd.notna(v) and v > 0])
        xs = [x + offsets[scheme] for x in x_centers]
        bars = ax.bar(
            xs,
            values,
            width=width,
            label=LABELS[scheme],
            color=COLORS[scheme],
            edgecolor="black",
            linewidth=0.55,
            hatch=HATCHES[scheme],
        )
        if annotate_est:
            for bar, value, est in zip(bars, values, est_flags):
                if est and pd.notna(value):
                    ax.text(
                        bar.get_x() + bar.get_width() / 2,
                        value * 1.18,
                        "est.",
                        ha="center",
                        va="bottom",
                        fontsize=4.9,
                    )
                if pd.isna(value):
                    ax.text(
                        bar.get_x() + bar.get_width() / 2,
                        1.0,
                        "n/a",
                        ha="center",
                        va="bottom",
                        fontsize=4.9,
                        color="#555",
                    )

    if all_values:
        if logy:
            ymin = max(min(all_values) * 0.55, 1e-3)
            ymax = max(all_values) * 2.0
        else:
            ymin = 0
            ymax = max(all_values) * 1.18
        ax.set_ylim(ymin, ymax)
    ax.set_xticks(x_centers)
    ax.set_xticklabels(dims)
    setup_axes(ax, "Dimension", ylabel, logy=logy)


def plot_prover_times(df: pd.DataFrame, out_dir: Path, *, logy: bool, suffix: str) -> None:
    fig, axes = plt.subplots(1, 2, figsize=FIGSIZE_PAIR)
    draw_grouped_bars(axes[0], df, "total_prove_excl_digest_s", "Prove (s)", logy=logy)
    axes[0].set_title("Excl. digest", pad=1.0)
    draw_grouped_bars(axes[1], df, "total_prove_incl_digest_s", "Prove (s)", logy=logy)
    axes[1].set_title("Incl. digest", pad=1.0)
    axes[1].legend(frameon=False, loc="upper left", bbox_to_anchor=(0.0, 1.03), handlelength=1.2)
    write_figure(fig, out_dir / f"scheme_prover_time_digest_sensitivity{suffix}.pdf")


def plot_verify_time(df: pd.DataFrame, out_dir: Path, *, logy: bool, suffix: str) -> None:
    fig, ax = plt.subplots(figsize=FIGSIZE_SINGLE)
    draw_grouped_bars(ax, df, "verify_ms", "Verify (ms)", annotate_est=False, logy=logy)
    ax.legend(frameon=False, loc="upper left", ncol=3, handlelength=1.2, columnspacing=0.8)
    write_figure(fig, out_dir / f"scheme_verify_time{suffix}.pdf")


def plot_setup_time(df: pd.DataFrame, out_dir: Path) -> None:
    fig, ax = plt.subplots(figsize=FIGSIZE_SINGLE)
    draw_grouped_bars(ax, df, "setup_s", "Setup (s)", annotate_est=False, logy=False)
    ax.legend(frameon=False, loc="upper left", ncol=3, handlelength=1.2, columnspacing=0.8)
    write_figure(fig, out_dir / "scheme_setup_time.pdf")


def plot_stage_breakdown_ours(df: pd.DataFrame, out_dir: Path) -> None:
    ours = df[df["scheme"] == "My Proposed"].set_index("dimension").loc[["2D", "3D"]]
    fig, ax = plt.subplots(figsize=FIGSIZE_SINGLE)
    x = range(len(ours))
    bottom = [0.0] * len(ours)
    components = [
        ("Digest", "digest_s", "#9ecae1"),
        ("Correct.", "correct_prove_s", "#2a9d8f"),
        ("Complete.", "complete_prove_s", "#f4a261"),
    ]
    for label, col, color in components:
        values = list(ours[col])
        ax.bar(x, values, bottom=bottom, color=color, edgecolor="black", linewidth=0.45, label=label)
        bottom = [b + v for b, v in zip(bottom, values)]
    ax.set_xticks(list(x))
    ax.set_xticklabels(list(ours.index))
    setup_axes(ax, "Dimension", "Ours prover stages (s)", logy=False)
    ax.legend(frameon=False, loc="upper left", ncol=3, handlelength=1.2, columnspacing=0.8)
    write_figure(fig, out_dir / "ours_stage_breakdown.pdf")


def draw_scheme_bars_for_dimension(
    ax: plt.Axes,
    sub: pd.DataFrame,
    metric: str,
    ylabel: str,
    *,
    logy: bool,
    annotate_est: bool = True,
) -> None:
    x = list(range(len(SCHEMES)))
    values = []
    est_flags = []
    for scheme in SCHEMES:
        row = sub[sub["scheme"] == scheme]
        if row.empty or pd.isna(row.iloc[0][metric]):
            values.append(float("nan"))
            est_flags.append(False)
        else:
            values.append(float(row.iloc[0][metric]))
            est_flags.append(bool(row.iloc[0]["estimated"]))

    for i, (scheme, value, est) in enumerate(zip(SCHEMES, values, est_flags)):
        if pd.isna(value):
            ax.text(i, 1.0, "n/a", ha="center", va="bottom", fontsize=4.9, color="#555")
            continue
        ax.bar(
            i,
            value,
            color=COLORS[scheme],
            edgecolor="black",
            linewidth=0.55,
            hatch=HATCHES[scheme],
        )
        if annotate_est and est:
            ax.text(i, value * (1.15 if logy else 1.02), "est.", ha="center", va="bottom", fontsize=4.9)

    finite = [v for v in values if pd.notna(v) and v > 0]
    if finite:
        if logy:
            ax.set_ylim(max(min(finite) * 0.55, 1e-3), max(finite) * 2.0)
        else:
            ax.set_ylim(0, max(finite) * 1.18)
    ax.set_xticks(x)
    ax.set_xticklabels([LABELS[s] for s in SCHEMES], rotation=20, ha="right")
    setup_axes(ax, "", ylabel, logy=logy)


def plot_dimension_summary(df: pd.DataFrame, out_dir: Path, dimension: str, *, logy: bool, suffix: str) -> None:
    sub = df[df["dimension"] == dimension]
    fig, axes = plt.subplots(2, 2, figsize=FIGSIZE_DIM_SUMMARY)
    panels = [
        (axes[0, 0], "setup_s", "Setup (s)", False),
        (axes[0, 1], "total_prove_excl_digest_s", "Prove excl. (s)", True),
        (axes[1, 0], "total_prove_incl_digest_s", "Prove incl. (s)", True),
        (axes[1, 1], "verify_ms", "Verify (ms)", False),
    ]
    for ax, metric, ylabel, allow_est in panels:
        draw_scheme_bars_for_dimension(ax, sub, metric, ylabel, logy=logy, annotate_est=allow_est)
    axes[0, 0].set_title(f"{dimension}", pad=1.0)
    write_figure(fig, out_dir / f"scheme_{dimension.lower()}_summary{suffix}.pdf")


def main() -> None:
    args = parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    df = read_data(Path(args.data))
    plot_prover_times(df, out_dir, logy=True, suffix="")
    plot_prover_times(df, out_dir, logy=False, suffix="_linear")
    plot_verify_time(df, out_dir, logy=True, suffix="")
    plot_verify_time(df, out_dir, logy=False, suffix="_linear")
    plot_setup_time(df, out_dir)
    plot_stage_breakdown_ours(df, out_dir)
    for dimension in ["2D", "3D"]:
        plot_dimension_summary(df, out_dir, dimension, logy=True, suffix="")
        plot_dimension_summary(df, out_dir, dimension, logy=False, suffix="_linear")


if __name__ == "__main__":
    main()
