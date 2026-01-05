from __future__ import annotations
import pandas as pd

from src.config import Paths
from src.utils.io import read_csv, write_csv, write_json


REASON_TEXT = {
    "contrib_failed_burst": "Repeated failed logins from the same source IP (burst behavior)",
    "contrib_unusual_hour": "Activity during unusual hours (higher risk window)",
    "contrib_high_risk_port": "High-risk port targeted (commonly abused / monitored)",
    "contrib_ip_reputation": "Source IP shows repeat-offender behavior (higher reputation risk)",
}


def explain_top_reasons(row: pd.Series, top_k: int = 3) -> list[str]:
    contrib_cols = [
        "contrib_failed_burst",
        "contrib_unusual_hour",
        "contrib_high_risk_port",
        "contrib_ip_reputation",
    ]
    items = [(c, float(row[c])) for c in contrib_cols]
    items.sort(key=lambda x: x[1], reverse=True)

    reasons = []
    for col, val in items[:top_k]:
        if val > 0.0001:
            reasons.append(REASON_TEXT[col])
    return reasons


def main() -> None:
    paths = Paths()
    scored = read_csv(paths.processed_scored_csv)

    # Pick the top 25 highest risk alerts as “sample outputs”
    top = scored.sort_values("risk_score", ascending=False).head(25).copy()
    top["explanations"] = top.apply(lambda r: explain_top_reasons(r, top_k=3), axis=1)

    # Optional ATT&CK summary string (nice for SOC readability)
    top["attack_summary"] = top.apply(
        lambda r: f'{r["attack_tactic"]} / {r["attack_technique"]} ({r["attack_technique_id"]})',
        axis=1
    )

    # Save a recruiter-friendly sample CSV + JSON
    sample_cols = [
        "alert_id",
        "timestamp",
        "source_ip",
        "destination_ip",
        "event_type",
        "port",
        "severity",

        # MITRE ATT&CK
        "attack_tactic",
        "attack_technique",
        "attack_technique_id",
        "attack_summary",

        "risk_score",
        "risk_level",
        "explanations",
    ]

    write_csv(top[sample_cols], paths.sample_scored_csv)

    json_obj = top[sample_cols].to_dict(orient="records")
    write_json(json_obj, paths.sample_scored_json)

    print(f"[OK] Wrote sample CSV:  {paths.sample_scored_csv}")
    print(f"[OK] Wrote sample JSON: {paths.sample_scored_json}")


if __name__ == "__main__":
    main()
