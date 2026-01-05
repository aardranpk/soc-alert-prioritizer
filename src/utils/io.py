from __future__ import annotations
import json
import os
from typing import Any
import pandas as pd


def ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def read_csv(path: str) -> pd.DataFrame:
    return pd.read_csv(path)


def write_csv(df: pd.DataFrame, path: str) -> None:
    ensure_parent_dir(path)
    df.to_csv(path, index=False)


def write_json(obj: Any, path: str) -> None:
    ensure_parent_dir(path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
