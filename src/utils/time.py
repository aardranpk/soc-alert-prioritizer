from __future__ import annotations
import pandas as pd


def to_datetime(series: pd.Series) -> pd.Series:
    return pd.to_datetime(series, errors="coerce", utc=True)
