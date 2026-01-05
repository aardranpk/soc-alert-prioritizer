from __future__ import annotations
import numpy as np
import pandas as pd

from src.config import Paths, ScoringSettings
from src.utils.io import read_csv, write_csv


def score_row(row: pd.Series, settings: ScoringSettings) -> dict:
    # Normalize failed burst roughly: 0..1 based on a cap
    failed_cap = 12
    failed_norm = min(float(row["failed_count_last_window"]) / failed_cap, 1.0)

    unusual = float(row["is_unusual_hour"])
    risky_port = float(row["is_high_risk_port"])
    rep = float(row["ip_repeat_score"])

    # Weighted sum, clipped to 0..1
    score = (
        settings.w_failed_burst * failed_norm
        + settings.w_unusual_hour * unusual
        + settings.w_high_risk_port * risky_port
        + settings.w_ip_reputation * rep
    )
    score = float(np.clip(score, 0, 1))

    # Level
    if score >= settings.high_risk_threshold:
        level = "HIGH"
    elif score >= settings.medium_risk_threshold:
        level = "MEDIUM"
    else:
        level = "LOW"

    # Contributions (for explainability)
    contribs = {
        "failed_burst": settings.w_failed_burst * failed_norm,
        "unusual_hour": settings.w_unusual_hour * unusual,
        "high_risk_port": settings.w_high_risk_port * risky_port,
        "ip_reputation": settings.w_ip_reputation * rep,
    }

    return {"risk_score": score, "risk_level": level, "contribs": contribs}


def score_alerts(df: pd.DataFrame) -> pd.DataFrame:
    settings = ScoringSettings()
    df = df.copy()

    results = df.apply(lambda r: score_row(r, settings), axis=1)
    df["risk_score"] = results.map(lambda x: x["risk_score"])
    df["risk_level"] = results.map(lambda x: x["risk_level"])
    df["contrib_failed_burst"] = results.map(lambda x: x["contribs"]["failed_burst"])
    df["contrib_unusual_hour"] = results.map(lambda x: x["contribs"]["unusual_hour"])
    df["contrib_high_risk_port"] = results.map(lambda x: x["contribs"]["high_risk_port"])
    df["contrib_ip_reputation"] = results.map(lambda x: x["contribs"]["ip_reputation"])

    return df


def main() -> None:
    paths = Paths()
    feats = read_csv(paths.processed_features_csv)
    scored = score_alerts(feats)
    write_csv(scored, paths.processed_scored_csv)
    print(f"[OK] Wrote scored alerts: {paths.processed_scored_csv} ({len(scored)} rows)")


if __name__ == "__main__":
    main()
