import asyncio
import os
import subprocess
import time
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet
from loguru import logger

from tracecat import config
from tracecat.db.schemas import Secret
from tracecat.secrets.encryption import encrypt_keyvalues
from tracecat.secrets.models import SecretKeyValue


def pytest_addoption(parser: pytest.Parser):
    parser.addoption(
        "--temporal-compose-file",
        action="store",
        default="../temporal/docker-compose/docker-compose.yml",
        help="Path to Temporal's docker-compose.yml file",
    )
    parser.addoption(
        "--temporal-no-restart",
        action="store_true",
        default=False,
        help="Do not restart the Temporal cluster if it is already running",
    )

    parser.addoption(
        "--tracecat-no-restart",
        action="store_true",
        default=False,
        help="Do not restart the Tracecat stack if it is already running",
    )


@pytest.fixture(autouse=True, scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(autouse=True, scope="session")
def monkeysession(request):
    mpatch = pytest.MonkeyPatch()
    yield mpatch
    mpatch.undo()


# NOTE: Don't auto-use this fixture unless necessary
@pytest.fixture(scope="session")
def auth_sandbox():
    from tracecat.contexts import ctx_role
    from tracecat.types.auth import Role

    service_role = Role(
        type="service", user_id="default-tracecat-user", service_id="tracecat-runner"
    )
    ctx_role.set(service_role)
    yield


@pytest.fixture(autouse=True, scope="session")
def env_sandbox(monkeysession: pytest.MonkeyPatch, request: pytest.FixtureRequest):
    logger.info("Setting up environment variables")
    temporal_compose_file = request.config.getoption("--temporal-compose-file")

    monkeysession.setattr(
        config,
        "TRACECAT__DB_URI",
        "postgresql+psycopg://postgres:postgres@localhost:5432/postgres",
    )

    monkeysession.setenv(
        "TRACECAT__DB_URI",
        "postgresql+psycopg://postgres:postgres@localhost:5432/postgres",
    )
    monkeysession.setenv("TRACECAT__DB_ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeysession.setenv("TRACECAT__API_URL", "http://api:8000")
    monkeysession.setenv("TRACECAT__PUBLIC_RUNNER_URL", "http://localhost:8001")
    monkeysession.setenv("TRACECAT__SERVICE_KEY", "test-service-key")
    monkeysession.setenv("TEMPORAL__DOCKER_COMPOSE_PATH", temporal_compose_file)
    # When launching the worker directly in a test, use localhost
    # If the worker is running inside a container, use host.docker.internal
    monkeysession.setenv("TEMPORAL__CLUSTER_URL", "http://localhost:7233")
    monkeysession.setenv("TEMPORAL__CLUSTER_QUEUE", "test-tracecat-task-queue")
    monkeysession.setenv("TEMPORAL__CLUSTER_NAMESPACE", "default")
    yield
    # Cleanup is automatic with monkeypatch
    logger.info("Environment variables cleaned up")


@pytest.fixture(scope="session")
def create_mock_secret(auth_sandbox):
    def _get_secret(secret_name: str, secrets: dict[str, str]) -> list[Secret]:
        keys = [SecretKeyValue(key=k, value=v) for k, v in secrets.items()]
        new_secret = Secret(
            owner_id=uuid4().hex,  # Assuming owner_id should be unique per secret
            id=uuid4().hex,  # Generate a unique ID for each secret
            name=secret_name,
            type="custom",  # Assuming a fixed type; adjust as necessary
            encrypted_keys=encrypt_keyvalues(
                keys, key=os.environ["TRACECAT__DB_ENCRYPTION_KEY"]
            ),
        )
        return new_secret

    return _get_secret


@pytest.fixture(scope="session")
def temporal_cluster(pytestconfig: pytest.Config, env_sandbox):
    compose_file = os.environ["TEMPORAL__DOCKER_COMPOSE_PATH"]
    logger.info(
        "Setting up Temporal cluster",
        compose_file=compose_file,
    )

    no_restart = pytestconfig.getoption("--temporal-no-restart")
    if no_restart:
        logger.info("Skipping Temporal cluster setup")
        yield
    else:
        try:
            subprocess.run(
                ["docker", "compose", "-f", compose_file, "up", "-d"], check=True
            )
            time.sleep(10)  # Wait for the cluster to start
            logger.info("Temporal started")

            yield  # Run the tests

        finally:
            logger.info("Shutting down Temporal cluster")
            subprocess.run(
                ["docker", "compose", "-f", compose_file, "down", "--remove-orphans"],
                check=True,
            )
            logger.info("Successfully shut down Temporal cluster")


@pytest.fixture(scope="session")
def tracecat_stack(pytestconfig: pytest.Config, env_sandbox):
    logger.info("Setup Tracecat stack")
    no_restart = pytestconfig.getoption("--tracecat-no-restart")
    if no_restart:
        logger.info("Skipping Tracecat stack setup")
        yield
    else:
        try:
            subprocess.run(
                ["docker", "compose", "up", "-d", "api", "postgres_db"], check=True
            )
            time.sleep(5)  # Wait for the cluster to start
            logger.info("Tracecat stack started")

            yield
        finally:
            logger.info("Shutting down Tracecat stack")
            subprocess.run(
                ["docker", "compose", "down", "--remove-orphans"], check=True
            )
            logger.info("Successfully shut down Tracecat stack")


@pytest.fixture(scope="session")
def tracecat_worker(env_sandbox):
    # Start the Tracecat Temporal worker
    # The worker is in our main tracecat docker compose file
    try:
        # Check that worker is not already running
        logger.info("Starting Tracecat Temporal worker")
        env_copy = os.environ.copy()
        # As the worker is running inside a container, use host.docker.internal
        env_copy["TEMPORAL__CLUSTER_URL"] = "http://host.docker.internal:7233"
        subprocess.run(
            ["docker", "compose", "up", "-d", "worker"],
            check=True,
            env=env_copy,
        )
        time.sleep(5)

        yield
    finally:
        logger.info("Stopping Tracecat Temporal worker")
        subprocess.run(
            ["docker", "compose", "down", "--remove-orphans", "worker"], check=True
        )
        logger.info("Stopped Tracecat Temporal worker")
