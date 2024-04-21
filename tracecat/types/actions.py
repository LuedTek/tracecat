from typing import Literal

ActionType = Literal[
    # Core primitives
    "webhook",
    "http_request",
    "data_transform",
    "condition.compare",
    "condition.regex",
    "condition.membership",
    "llm.extract",
    "llm.label",
    "llm.translate",
    "llm.choice",
    "llm.summarize",
    "send_email",
    "receive_email",
    "open_case",
    # Integrations
    "integrations.datadog.list_security_signals",
    "integrations.datadog.update_security_signal_state",
    "integrations.datadog.list_detection_rules",
]
