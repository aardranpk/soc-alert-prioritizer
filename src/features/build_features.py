from __future__ import annotations
import numpy as np
import pandas as pd

from src.config import Paths, FeatureSettings, ScoringSettings
from src.utils.io import read_csv, write_csv
from src.utils.time import to_datetime


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    feat_settings = FeatureSettings()
    score_settings = ScoringSettings()

    df = df.copy()
    df["timestamp_dt"] = to_datetime(df["timestamp"])
    df = df.sort_values("timestamp_dt").reset_index(drop=True)

    # Unusual hour feature
    df["hour"] = df["timestamp_dt"].dt.hour
    df["is_unusual_hour"] = df["hour"].isin(feat_settings.unusual_hours).astype(int)

    # High risk port feature
    df["is_high_risk_port"] = df["port"].isin(score_settings.high_risk_ports).astype(int)

    # Severity numeric mapping
    sev_map = {"low": 0, "medium": 1, "high": 2}
    df["severity_num"] = df["severity"].map(sev_map).fillna(0).astype(int)

    # Failed login burst in last N minutes per source_ip
    window = f"{feat_settings.window_minutes}min"
    df["is_failed_login"] = (df["event_type"] == "FAILED_LOGIN").astype(int)

    # Rolling sum per IP using time-based rolling
    out = []
    for ip, g in df.groupby("source_ip", sort=False):
        g = g.sort_values("timestamp_dt")
        # Set index to time for rolling window
        g = g.set_index("timestamp_dt")
        g["failed_count_last_window"] = g["is_failed_login"].rolling(window).sum().fillna(0).astype(int)
        g = g.reset_index()
        out.append(g)

    df = pd.concat(out, ignore_index=True).sort_values("timestamp_dt").reset_index(drop=True)

    # Mock “IP reputation” score: repeat offenders get higher rep score
    # (You can later replace with real intel feeds)
    ip_counts = df["source_ip"].value_counts()
    df["ip_repeat_score"] = df["source_ip"].map(lambda x: float(ip_counts.get(x, 1)))
    # normalize 0..1
    max_c = df["ip_repeat_score"].max()
    df["ip_repeat_score"] = (df["ip_repeat_score"] / max_c).clip(0, 1)

    # Keep only needed columns for next steps
    feat_cols = [
        "alert_id",
        "timestamp",
        "source_ip",
        "destination_ip",
        "event_type",
        "port",
        "severity",
        "username",
        "failed_count_last_window",
        "is_unusual_hour",
        "is_high_risk_port",
        "ip_repeat_score",
        "severity_num",
    ]
    return df[feat_cols]


def main() -> None:
    paths = Paths()
    raw = read_csv(paths.raw_alerts_csv)
    feats = build_features(raw)
    write_csv(feats, paths.processed_features_csv)
    print(f"[OK] Wrote features: {paths.processed_features_csv} ({len(feats)} rows)")


if __name__ == "__main__":
    main()
