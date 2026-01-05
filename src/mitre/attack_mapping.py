from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, Tuple


@dataclass(frozen=True)
class AttackMapping:
    tactic: str
    technique: str
    technique_id: str


# NOTE:
# This is a practical starter mapping for common SOC alert categories.
# You can refine/expand based on your dataset/event taxonomy later.
EVENT_TO_ATTACK: Dict[str, AttackMapping] = {
    "FAILED_LOGIN": AttackMapping(
        tactic="Credential Access",
        technique="Brute Force",
        technique_id="T1110",
    ),
    "SUCCESS_LOGIN": AttackMapping(
        tactic="Initial Access",
        technique="Valid Accounts",
        technique_id="T1078",
    ),
    "PORT_SCAN": AttackMapping(
        tactic="Discovery",
        technique="Network Service Discovery",
        technique_id="T1046",
    ),
    "SUSPICIOUS_DNS": AttackMapping(
        tactic="Command and Control",
        technique="Application Layer Protocol",
        technique_id="T1071",
    ),
    "MALWARE_ALERT": AttackMapping(
        tactic="Execution",
        technique="User Execution",
        technique_id="T1204",
    ),
    "PRIV_ESC_ATTEMPT": AttackMapping(
        tactic="Privilege Escalation",
        technique="Exploitation for Privilege Escalation",
        technique_id="T1068",
    ),
}


DEFAULT_ATTACK = AttackMapping(
    tactic="Unknown",
    technique="Unknown",
    technique_id="N/A",
)


def map_event_to_attack(event_type: str) -> AttackMapping:
    return EVENT_TO_ATTACK.get(event_type, DEFAULT_ATTACK)
