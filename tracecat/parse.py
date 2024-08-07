from collections.abc import Iterator
from typing import Any
from urllib.parse import parse_qs, urlparse


def insert_obj_by_path(
    obj: dict[str, Any], *, path: str, value: Any, sep: str = "."
) -> None:
    *stem, leaf = path.split(sep=sep)
    for key in stem:
        obj = obj.setdefault(key, {})
    obj[leaf] = value


def reconstruct_obj(flat_kv: dict[str, Any], *, sep: str = ".") -> dict[str, Any]:
    """Parse a flat key-value dictionary into a nested dictionary.

    Keys are expected to be delimiter-separated paths.
    """
    obj = {}
    for path, value in flat_kv.items():
        if isinstance(value, list) and len(value) == 1:
            value = value[0]
        insert_obj_by_path(obj, path=path, value=value, sep=sep)
    return obj


def parse_child_webhook(
    url: str, additional_qs: list[str] | None = None
) -> dict[str, Any] | None:
    """Return the reconstructed payload and metadata from a child webhook URL."""
    parsed_url = urlparse(url)
    # Dot delimited keys
    query = parsed_url.query
    if additional_qs:
        query += "&" + "&".join(additional_qs)
    query_kv = parse_qs(query)
    payload = reconstruct_obj(query_kv)
    endpoint, path, secret = parsed_url.path.strip("/").split("/")
    if endpoint != "webhooks":
        return None

    return {
        "payload": payload,
        "path": path,
        "secret": secret,
    }


def traverse_leaves(obj: Any, parent_key: str = "") -> Iterator[tuple[str, Any]]:
    """Iterate through the leaves of a nested dictionary.

    Each iterations returns the location (jsonpath) and the value.
    """
    if isinstance(obj, dict):
        for key, value in obj.items():
            new_key = f"{parent_key}.{key}" if parent_key else key
            yield from traverse_leaves(value, new_key)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            new_key = f"{parent_key}[{i}]"
            yield from traverse_leaves(item, new_key)
    else:
        yield parent_key, obj
