from dataclasses import dataclass

@dataclass(frozen=True)
class Paths:
    raw_alerts_csv: str = "data/raw/alerts_synthetic.csv"
    processed_features_csv: str = "data/processed/alerts_features.csv"
    processed_scored_csv: str = "data/processed/alerts_scored.csv"

    sample_scored_json: str = "reports/sample_outputs/scored_alerts_sample.json"
    sample_scored_csv: str = "reports/sample_outputs/scored_alerts_sample.csv"

    fig_score_dist: str = "reports/figures/score_distribution.png"
    fig_top_reasons: str = "reports/figures/top_reasons.png"
    fig_high_risk_examples: str = "reports/figures/high_risk_alert_examples.png"
    fig_top_attack_techniques: str = "reports/figures/top_attack_techniques.png"


@dataclass(frozen=True)
class GenerateSettings:
    n_alerts: int = 2500
    seed: int = 42


@dataclass(frozen=True)
class FeatureSettings:
    window_minutes: int = 10
    unusual_hours: tuple = (0, 1, 2, 3, 4, 5)  # night hours


@dataclass(frozen=True)
class ScoringSettings:
    # Weights (rule-based SOC style). Adjust later if you want.
    w_failed_burst: float = 0.35
    w_unusual_hour: float = 0.20
    w_high_risk_port: float = 0.20
    w_ip_reputation: float = 0.25

    # Thresholds
    high_risk_threshold: float = 0.75
    medium_risk_threshold: float = 0.45

    # Define “high risk” ports commonly used in attacks or commonly monitored
    high_risk_ports: tuple = (22, 23, 3389, 445, 135, 139, 5900, 8080, 8443)
