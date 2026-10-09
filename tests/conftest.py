import secrets
import pytest


@pytest.fixture
def workspace(tmp_path):
    root = tmp_path / "monitored"
    root.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    keys = tmp_path / "keys"
    keys.mkdir()
    key = keys / "authentication.key"
    key.write_bytes(secrets.token_bytes(32))
    return root, state / "baseline.db", key
