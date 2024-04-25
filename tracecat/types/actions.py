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
    "integrations.aws_cloudtrail.query_cloudtrail_logs",
    "integrations.datadog.list_detection_rules",
    "integrations.datadog.list_security_signals",
    "integrations.datadog.update_security_signal_state",
    "integrations.emailrep.check_email_reputation",
    "integrations.urlscan.analyze_url",
    "integrations.virustotal.get_domain_report",
    "integrations.virustotal.get_file_report",
    "integrations.virustotal.get_ip_address_report",
    "integrations.virustotal.get_url_report",
]
