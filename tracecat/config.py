from pathlib import Path

MAX_RETRIES = 3

TRACECAT__OAUTH2_GMAIL_PATH = (
    Path("~/tracecat-runner-client-secret.json").expanduser().resolve()
)