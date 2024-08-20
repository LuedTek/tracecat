"""Sublime Security integration.

Sublime:
  Authentication method: Token

Requires: A secret named `sublime` with the following keys:
- `SUBLIME_BASE_URL`
- `SUBLIME_API_TOKEN`

EmailRep:
  Authentication method: None

References: https://docs.sublimesecurity.com/reference
Supported APIs:

```python
sublime_analyze_email = {
    "endpoint": "/explore.php?",
    "method": "GET",
    "ocsf_schema": "",
    "reference": "https://emailrep.io"
}
sublime_analyze_link = {
    "endpoint": "/explore.php?",
    "method": "GET",
    "ocsf_schema": "",
    "reference": "https://api.platform.sublimesecurity.com/messages"
}
get_sublime_message_group = {
    "endpoint": "/explore.php?",
    "method": "GET",
    "ocsf_schema": "",
    "reference": "https://pulsedive.com/api/explore"
}
get_sublime_message_data_model = {
    "endpoint": "/explore.php?",
    "method": "GET",
    "ocsf_schema": "",
    "reference": "https://pulsedive.com/api/explore"
}
get_sublime_message_attack_score = {
    "endpoint": "/explore.php?",
    "method": "GET",
    "ocsf_schema": "",
    "reference": "https://pulsedive.com/api/explore"
}
review_sublime_message_group= {
    "endpoint": "/explore.php?",
    "method": "GET",
    "ocsf_schema": "",
    "reference": "https://pulsedive.com/api/explore"
} 
```
"""
import os
from typing import Annotated, Any, Literal

import httpx

from tracecat.registry import Field, RegistrySecret, registry 

EMAILREP_BASE_URL = "https://emailrep.io"
MESSAGE_GROUP_ENDPOINT = "/message-groups/" # Alerts
MESSAGE_ENDPOINT = "/messages/"
BINEXPLODE_ENDPOINT = "/binexplode/"
ENRICHMENT_ENDPOINT = "/enrichment/"

sublime_secret = RegistrySecret(
    name="sublime",
    keys=["SUBLIME_BASE_URL", "SUBLIME_API_TOKEN", "EMAILREP_API_KEY"],
)

# --- EmailRep --- #
def create_emailrep_client() -> httpx.AsyncClient:
    EMAILREP_API_KEY = os.getenv("EMAILREP_API_KEY")
    if EMAILREP_API_KEY == 'free':
      raise Warning("EMAILREP_API_KEY is not set - using free 10/day limit")
      headers = {"User-Agent": "tracecat-client"}
    else: 
      headers = {"User-Agent": "tracecat-client", "Key": EMAILREP_API_KEY}
    return httpx.AsyncClient(base_url=EMAILREP_BASE_URL, headers=headers)

# --- Sublime --- #
def create_sublime_client(api_version: str = "v0") -> httpx.AsyncClient:
    SUBLIME_BASE_URL = os.getenv("SUBLIME_BASE_URL")
    if SUBLIME_BASE_URL is None:
        SUBLIME_BASE_URL = "https://api.platform.sublimesecurity.com"
        raise Warning("SUBLIME_BASE_URL is not set, using default value")
    client = httpx.AsyncClient(
        base_url=f'{SUBLIME_BASE_URL}/{api_version}',
        headers={
            "Authorization": f"Bearer {os.getenv('SUBLIME_API_TOKEN')}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
    )
    return client

# Enrichment
@registry.register(
    default_title="Analyze Email Address",
    description="Analyze an email address using Emailrep. ref: https://docs.sublime.security/reference/get_-email",
    display_group="Sublime Security",
    namespace="integrations.emailrep",
    secrets=[sublime_secret],
)
async def sublime_analyze_email(
    email: Annotated[str, Field(..., description="The email address to analyze.")],
) -> dict[str, Any]:
    async with create_emailrep_client() as client:
        response = await client.get(f"/email/{email}?summary=true")
        response.raise_for_status()
        return response.json()

@registry.register(
    default_title="Analyze Link",
    description="Analyze a provided link using Sublime's ml.link_analysis functionality. ref: https://docs.sublime.security/reference/linkanalysisevaluate-1",
    display_group="Sublime Security",
    namespace="integrations.sublime",
    secrets=[sublime_secret],
)
async def sublime_analyze_link(
  url: Annotated[str, Field(..., description="The url to perform analysis on.")],
) -> dict[str, Any]:
    async with create_sublime_client() as client:
        payload = { "url": url}
        response = await client.post(ENRICHMENT_ENDPOINT + 'link_analysis/evaluate', json=payload )
        response.raise_for_status()
        return response.json()

# Message Data / Enrichment Information
@registry.register(
    default_title="Get Sublime Alert Details",
    description="Get a Sublime message group (triggered alert) details from canonical (alert) id. This provides you all information in the alert detail, to then run further analysis through ref: https://docs.sublime.security/reference/getmessagegroup",
    display_group="Sublime Security",
    namespace="integrations.sublime",
    secrets=[sublime_secret],
)
async def get_sublime_message_group(
  canonical_id: Annotated[str, Field(..., description="The sublime canonical (alert) id to fetch")],
) -> dict[str, Any]:
    async with create_sublime_client() as client:
        response = await client.get(MESSAGE_GROUP_ENDPOINT + canonical_id)
        response.raise_for_status()
        return response.json()

@registry.register(
    default_title="Get Sublime Message Data Model",
    description="Get a Sublime Email Security message's data model from message_id. This is best ran through your LLM for FULL analysis / determination (at your own risk). ref: https://docs.sublime.security/reference/getmessagedatamodel-1",
    display_group="Sublime Security",
    namespace="integrations.sublime",
    secrets=[sublime_secret],
)
async def get_sublime_message_data_model(
  message_id: Annotated[str, Field(..., description="The sublime message id to fetch")],
) -> dict[str, Any]:
    async with create_sublime_client() as client:
        response = await client.get(MESSAGE_ENDPOINT + message_id + '/message_data_model')
        response.raise_for_status()
        return response.json()

@registry.register(
    default_title="Get Sublime Message Attack Score",
    description="Get a Sublime Email Security message's attack score (beta) by message_id. ref: https://docs.sublime.security/reference/getmessagedatamodel-1",
    display_group="Sublime Security",
    namespace="integrations.sublime",
    secrets=[sublime_secret],
)
async def get_sublime_message_attack_score(
  message_id: Annotated[str, Field(..., description="The sublime message id to fetch")],
) -> dict[str, Any]:
    async with create_sublime_client() as client:
        response = await client.get(MESSAGE_ENDPOINT + message_id + '/attack_score')
        response.raise_for_status()
        return response.json()


classificationTypes = Literal['malicious', 'benign', 'unwanted', 'simulation', 'skip']
actionTypes = Literal['restore', 'trash', 'move_to_spam', 'quarantine', 'warning_banner']

@registry.register(
    default_title="Review Sublime Message Group",
    description="Get a Sublime Email Security message's attack score (beta) by message_id. ref: https://docs.sublime.security/reference/getmessagedatamodel-1",
    display_group="Sublime Security",
    namespace="integrations.sublime",
    secrets=[sublime_secret],
)
async def review_sublime_message_group(
  classification: Annotated[classificationTypes, Field(..., description="The final review state of this message group.")],
  message_group_ids: Annotated[list, Field(..., description="The canonical_ids for the message groups you wish to classify")],
  action: Annotated[actionTypes, Field(..., description="the action that will occur upon review. Restore, trash, move_to_spam are free tier.")],
  custom_action_ids: Annotated[list, Field(..., description="custom actions created by user in actions settings. E.g. webhook to send to after review is completed.")],
  review_commnet: Annotated[str, Field(..., description="The comment attached to the review process - likely input determination reasoning.")],
  share_with_sublime: Annotated[bool, Field(..., description="Send analytics for sublime's identification program.")]
) -> dict[str, Any]:
    async with create_sublime_client() as client:
        payload = {
            "classification": classification,
            "message_group_ids": message_group_ids,
            "action": action,
            "custom_action_ids": ["tracecat_delete"],
            "review_comment": "${{ACTIONS.OPEN_AI.data}}",
            "share_with_sublime": True
        }
        response = await client.post(MESSAGE_GROUP_ENDPOINT + '/review', payload)
        response.raise_for_status()
        return response.json()

# TODO:
# BinExplode
# @registry.register(
#     default_title="Analyze Binary (Explode)",
#     description="Analyze binary using Sublime's BinaryExplode. ref: https://docs.sublime.security/reference/postscan-1; https://docs.sublime.security/reference/getscan-1",
#     display_group="Sublime Security",
#     namespace="integrations.sublime",
#     secrets=[sublime_secret],
# )
# async def sublime_analyze_binary(
#   message_id: Annotated[str, Field(..., description="The sublime message id to fetch")],
# ) -> dict[str, Any]:
#     async with create_sublime_client() as client:
#         response = await client.get( + message_id + '/attack_score')
#         response.raise_for_status()
#         return response.json()

# Searching
# Hunt POST
# url = "https://api.platform.sublimesecurity.com/v0/message-groups/hunt"

# payload = {
#     "created_at[lt]": None,
#     "created_at[gte]": "2024-06-04T15:09:26Z",
#     "source": "type.inbound and (   any(headers.ips,       regex.match(.ip,                 '18.205.140.116',                 '168.245.36.66'       )   ) ) or any(headers.hops, any(.fields, .name == \"x-phishtest-curricula\"))"
# }
# headers = {
#     "accept": "application/json",
#     "content-type": "application/json",
#     "authorization": "Bearer vtokncxbuxcb2xgy0q0mgu461x1refpsqy8n3fmxoimnnrn4z5mgxexxfkgxlf5v"
# }

# response = requests.post(url, json=payload, headers=headers)

# print(response.text)
#{"task_id":"bae25b79-71bb-4d76-9c72-4a85593ee41c"}

# Hunt GET
# url = "https://api.platform.sublimesecurity.com/v0/message-groups/hunt/bae25b79-71bb-4d76-9c72-4a85593ee41c"

# headers = {
#     "accept": "application/json",
#     "authorization": "Bearer vtokncxbuxcb2xgy0q0mgu461x1refpsqy8n3fmxoimnnrn4z5mgxexxfkgxlf5v"
# }

# response = requests.get(url, headers=headers)

# print(response.text)