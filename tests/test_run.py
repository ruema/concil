import pytest
from unittest.mock import MagicMock, patch
import os

with patch("ctypes.CDLL", return_value=MagicMock()):
    from concil import run


def test_read_environment_file(tmp_path):
    """Tests that read_environment_file reads an environment file correctly."""
    env_file = tmp_path / "env_file"
    env_file.write_text("FOO=bar\nBAZ=qux")
    env = run.read_environment_file(env_file)
    assert env == {"FOO": "bar", "BAZ": "qux"}


@pytest.fixture
def mock_abstract_config():
    """A pytest fixture for an AbstractConfig instance."""
    config = run.AbstractConfig()
    config.config = {
        "Env": ["FOO=bar", "BAZ"],
        "User": "1000:1000",
        "WorkingDir": "/app",
        "Entrypoint": ["/bin/sh", "-c"],
        "Cmd": ["echo hello"],
        "Volumes": {"/data": {}},
    }
    config.environment = {"BAZ": "qux"}
    return config


def test_abstract_config_get_environment(mock_abstract_config):
    """Tests AbstractConfig.get_environment."""
    env = mock_abstract_config.get_environment()
    assert env == {"FOO": "bar", "BAZ": "qux"}


def test_abstract_config_get_userid(mock_abstract_config):
    """Tests AbstractConfig.get_userid."""
    assert mock_abstract_config.get_userid() == (1000, 1000)


def test_abstract_config_working_dir(mock_abstract_config):
    """Tests AbstractConfig.working_dir."""
    assert mock_abstract_config.working_dir == "/app"


def test_abstract_config_build_commandline(mock_abstract_config):
    """Tests AbstractConfig.build_commandline."""
    cmd = mock_abstract_config.build_commandline()
    assert cmd == ["/bin/sh", "-c", "echo hello"]
    cmd = mock_abstract_config.build_commandline(args=["-v"])
    assert cmd == ["/bin/sh", "-c", "echo hello", "-v"]


def test_abstract_config_get_volumes(mock_abstract_config):
    """Tests AbstractConfig.get_volumes."""
    mock_abstract_config.volumes = ["/tmp:/data:ro"]
    volumes = mock_abstract_config.get_volumes()
    assert volumes == [("/tmp", "data", run.MS_RDONLY)]
