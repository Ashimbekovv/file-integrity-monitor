import secrets
import os
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


@pytest.fixture
def make_symlink():
    """Only skip link tests when Windows has not granted link-creation privilege."""
    def create(link, target, *, directory=False):
        try:
            link.symlink_to(target, target_is_directory=directory)
        except OSError as exc:
            if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
                pytest.skip("Windows requires Developer Mode or symlink privilege")
            raise
    return create
