from __future__ import annotations
import random
from datetime import datetime, timedelta, timezone
import numpy as np
import pandas as pd

from src.config import Paths, GenerateSettings
from src.utils.io import write_csv


EVENT_TYPES = [
    "FAILED_LOGIN",
    "SUCCESS_LOGIN",
    "PORT_SCAN",
    "MALWARE_ALERT",
    "SUSPICIOUS_DNS",
    "PRIV_ESC_ATTEMPT",
]

SEVERITIES = ["low", "medium", "high"]


def _random_ip(rng: np.random.Generator, private_only: bool = True) -> str:
    # Generates “private-ish” IPs for realism without using public ranges
    if private_only:
        choice = rng.integers(0, 3)
        if choice == 0:
            return f"10.{rng.integers(0,256)}.{rng.integers(0,256)}.{rng.integers(1,255)}"
        if choice == 1:
            return f"192.168.{rng.integers(0,256)}.{rng.integers(1,255)}"
        return f"172.{rng.integers(16,32)}.{rng.integers(0,256)}.{rng.integers(1,255)}"
    return f"{rng.integers(1,255)}.{rng.integers(0,256)}.{rng.integers(0,256)}.{rng.integers(1,255)}"


def generate_alerts(n_alerts: int, seed: int) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    random.seed(seed)

    # Time range: last 7 days from “now”
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=7)

    # Create a pool of “repeat offenders” IPs to simulate bursty attacks
    attacker_pool = [_random_ip(rng) for _ in range(30)]
    victim_pool = [_random_ip(rng) for _ in range(40)]

    rows = []
    for alert_id in range(1, n_alerts + 1):
        # Random timestamp across the 7-day range
        offset_seconds = int(rng.integers(0, int((now - start).total_seconds())))
        ts = start + timedelta(seconds=offset_seconds)

        event_type = rng.choice(EVENT_TYPES, p=[0.35, 0.20, 0.15, 0.10, 0.10, 0.10])

        # Make some alerts come from repeating attacker IPs
        if rng.random() < 0.55:
            source_ip = random.choice(attacker_pool)
        else:
            source_ip = _random_ip(rng)

        destination_ip = random.choice(victim_pool)

        # Port patterns by event type
        if event_type in ("FAILED_LOGIN", "SUCCESS_LOGIN", "PRIV_ESC_ATTEMPT"):
            port = int(rng.choice([22, 3389, 445, 80, 443], p=[0.25, 0.25, 0.15, 0.20, 0.15]))
        elif event_type == "PORT_SCAN":
            port = int(rng.choice([22, 23, 80, 443, 445, 3389, 8080, 8443], p=[0.12,0.08,0.20,0.20,0.12,0.12,0.08,0.08]))
        elif event_type == "SUSPICIOUS_DNS":
            port = 53
        else:
            port = int(rng.choice([80, 443, 445, 3389, 8080, 8443], p=[0.25,0.25,0.15,0.15,0.10,0.10]))

        # Severity depends on event type
        if event_type in ("MALWARE_ALERT", "PRIV_ESC_ATTEMPT"):
            severity = rng.choice(SEVERITIES, p=[0.10, 0.30, 0.60])
        elif event_type in ("FAILED_LOGIN", "PORT_SCAN", "SUSPICIOUS_DNS"):
            severity = rng.choice(SEVERITIES, p=[0.30, 0.50, 0.20])
        else:
            severity = rng.choice(SEVERITIES, p=[0.50, 0.40, 0.10])

        username = rng.choice(["admin", "root", "svc_backup", "jdoe", "asmith", "guest"], p=[0.10,0.06,0.10,0.32,0.32,0.10])

        rows.append(
            {
                "alert_id": alert_id,
                "timestamp": ts.isoformat(),
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "event_type": event_type,
                "port": port,
                "severity": severity,
                "username": username,
            }
        )

    df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
    return df


def main() -> None:
    paths = Paths()
    settings = GenerateSettings()

    df = generate_alerts(settings.n_alerts, settings.seed)
    write_csv(df, paths.raw_alerts_csv)

    print(f"[OK] Wrote synthetic alerts: {paths.raw_alerts_csv} ({len(df)} rows)")


if __name__ == "__main__":
    main()
