import os

import pytest
from httpx import AsyncClient

from tracecat.auth.clients import AuthenticatedAPIClient, AuthenticatedServiceClient
from tracecat.config import TRACECAT__API_URL
from tracecat.contexts import ctx_role
from tracecat.types.auth import Role


@pytest.mark.asyncio
async def test_authenticated_service_client():
    service_role = Role(
        type="service", user_id="mock_user_id", service_id="mock_service_id"
    )
    async with AuthenticatedServiceClient(role=service_role) as client:
        assert isinstance(client, AsyncClient)
        assert client.role == service_role
        assert client.headers["Service-Role"] == "mock_service_id"
        assert client.headers["X-API-Key"] == os.environ["TRACECAT__SERVICE_KEY"]
        assert client.headers["Service-User-ID"] == "mock_user_id"

    service_role = Role(type="service", service_id="mock_service_id")
    async with AuthenticatedServiceClient(role=service_role) as client:
        assert isinstance(client, AsyncClient)
        assert client.role == service_role
        assert client.headers["Service-Role"] == "mock_service_id"
        assert client.headers["X-API-Key"] == os.environ["TRACECAT__SERVICE_KEY"]
        assert "Service-User-ID" not in client.headers


@pytest.mark.asyncio
async def test_authenticated_service_client_init_with_role():
    # Test initialization of AuthenticatedServiceClient
    role = Role(type="service", user_id="mock_user_id", service_id="mock_service_id")
    async with AuthenticatedServiceClient(role=role) as client:
        assert isinstance(client, AsyncClient)
        assert client.role == role
        assert client.headers["Service-Role"] == "mock_service_id"
        assert client.headers["X-API-Key"] == os.environ["TRACECAT__SERVICE_KEY"]
        assert client.headers["Service-User-ID"] == "mock_user_id"


@pytest.mark.asyncio
async def test_authenticated_service_client_init_no_role():
    """Test initialization of AuthenticatedServiceClient without role

    Expect:
    - role is the default role
    - headers are set with the default role
    - no user id in the headers
    """

    default_role = Role(type="service", service_id="tracecat-service")
    async with AuthenticatedServiceClient() as client:
        assert isinstance(client, AsyncClient)
        assert client.role == default_role
        assert client.headers["Service-Role"] == "tracecat-service"
        assert client.headers["X-API-Key"] == os.environ["TRACECAT__SERVICE_KEY"]
        assert "Service-User-ID" not in client.headers


@pytest.mark.asyncio
async def test_authenticated_service_client_init_role_from_context():
    # Test initialization of AuthenticatedServiceClient without role
    mock_ctx_role = Role(
        type="service",
        user_id="mock_ctx_user_id",
        service_id="mock_ctx_service_id",
    )
    ctx_role.set(mock_ctx_role)

    async with AuthenticatedServiceClient() as client:
        assert client.role == mock_ctx_role
        assert client.headers["Service-Role"] == "mock_ctx_service_id"
        assert client.headers["X-API-Key"] == os.environ["TRACECAT__SERVICE_KEY"]
        assert client.headers["Service-User-ID"] == "mock_ctx_user_id"


@pytest.mark.asyncio
async def test_authenticated_api_client_init_role_from_context():
    # Test initialization of AuthenticatedAPIClient without role
    mock_ctx_role = Role(
        type="service",
        user_id="mock_ctx_user_id",
        service_id="mock_ctx_service_id",
    )
    ctx_role.set(mock_ctx_role)

    async with AuthenticatedAPIClient() as client:
        assert client.role == mock_ctx_role
        assert client.headers["Service-Role"] == "mock_ctx_service_id"
        assert client.headers["X-API-Key"] == os.environ["TRACECAT__SERVICE_KEY"]
        assert client.headers["Service-User-ID"] == "mock_ctx_user_id"
        assert client.base_url == TRACECAT__API_URL


@pytest.mark.asyncio
async def test_authenticated_api_client_init_no_role():
    # Test initialization of AuthenticatedAPIClient without role
    default_role = Role(type="service", service_id="tracecat-service")
    async with AuthenticatedAPIClient() as client:
        assert client.role == default_role
        assert client.headers["Service-Role"] == "tracecat-service"
        assert client.headers["X-API-Key"] == os.environ["TRACECAT__SERVICE_KEY"]
        assert "Service-User-ID" not in client.headers
        assert client.base_url == TRACECAT__API_URL


@pytest.mark.asyncio
async def test_authenticated_api_client_init_with_role():
    # Test initialization of AuthenticatedAPIClient
    role = Role(type="service", user_id="mock_user_id", service_id="mock_service_id")
    async with AuthenticatedAPIClient(role=role) as client:
        assert isinstance(client, AsyncClient)
        assert client.role == role
        assert client.headers["Service-Role"] == "mock_service_id"
        assert client.headers["X-API-Key"] == os.environ["TRACECAT__SERVICE_KEY"]
        assert client.headers["Service-User-ID"] == "mock_user_id"
        assert client.base_url == TRACECAT__API_URL

    role = Role(type="service", service_id="mock_service_id")
    async with AuthenticatedAPIClient(role=role) as client:
        assert client.role == role
        assert client.headers["Service-Role"] == "mock_service_id"
        assert client.headers["X-API-Key"] == os.environ["TRACECAT__SERVICE_KEY"]
        assert "Service-User-ID" not in client.headers
        assert client.base_url == TRACECAT__API_URL
