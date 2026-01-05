from __future__ import annotations

from src.data_gen.generate_alerts import main as gen_main
from src.features.build_features import main as feat_main
from src.scoring.rule_engine import main as score_main
from src.explain.explain_rules import main as explain_main
from src.evaluation.metrics import main as metrics_main


def main() -> None:
    # End-to-end pipeline
    gen_main()       # -> data/raw/alerts_synthetic.csv
    feat_main()      # -> data/processed/alerts_features.csv
    score_main()     # -> data/processed/alerts_scored.csv
    explain_main()   # -> reports/sample_outputs/scored_alerts_sample.csv + .json
    metrics_main()   # -> reports/figures/*.png

    print("[DONE] Pipeline complete ✅")


if __name__ == "__main__":
    main()
