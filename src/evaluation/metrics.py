from __future__ import annotations
import pandas as pd
import matplotlib.pyplot as plt

from src.config import Paths
from src.utils.io import read_csv, ensure_parent_dir


def plot_score_distribution(df: pd.DataFrame, out_path: str) -> None:
    ensure_parent_dir(out_path)
    plt.figure()
    plt.hist(df["risk_score"], bins=30)
    plt.title("Risk Score Distribution")
    plt.xlabel("risk_score")
    plt.ylabel("count")
    plt.tight_layout()
    plt.savefig(out_path, dpi=160)
    plt.close()


def plot_top_reasons_mean(df: pd.DataFrame, out_path: str) -> None:
    ensure_parent_dir(out_path)
    cols = {
        "Failed burst": "contrib_failed_burst",
        "Unusual hour": "contrib_unusual_hour",
        "High-risk port": "contrib_high_risk_port",
        "IP reputation": "contrib_ip_reputation",
    }
    means = {k: float(df[v].mean()) for k, v in cols.items()}

    plt.figure()
    plt.bar(list(means.keys()), list(means.values()))
    plt.title("Average Contribution by Rule (Proxy for Importance)")
    plt.xlabel("rule")
    plt.ylabel("mean contribution")
    plt.xticks(rotation=20, ha="right")
    plt.tight_layout()
    plt.savefig(out_path, dpi=160)
    plt.close()


def plot_high_risk_examples(df: pd.DataFrame, out_path: str) -> None:
    ensure_parent_dir(out_path)
    high = df[df["risk_level"] == "HIGH"].copy()
    top_ips = high["source_ip"].value_counts().head(10)

    plt.figure()
    plt.bar(top_ips.index.astype(str), top_ips.values)
    plt.title("Top Source IPs in HIGH Risk Alerts (Top 10)")
    plt.xlabel("source_ip")
    plt.ylabel("high-risk alert count")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(out_path, dpi=160)
    plt.close()


def main() -> None:
    paths = Paths()
    df = read_csv(paths.processed_scored_csv)

    plot_score_distribution(df, paths.fig_score_dist)
    plot_top_reasons_mean(df, paths.fig_top_reasons)
    plot_high_risk_examples(df, paths.fig_high_risk_examples)

    print(f"[OK] Wrote figure: {paths.fig_score_dist}")
    print(f"[OK] Wrote figure: {paths.fig_top_reasons}")
    print(f"[OK] Wrote figure: {paths.fig_high_risk_examples}")


if __name__ == "__main__":
    main()
