from unittest.mock import MagicMock

import pytest

from concil import store


@pytest.fixture
def mock_config():
    """A pytest fixture that returns a mock ConcilConfig instance."""
    config = MagicMock()
    config.cache_dir = "/cache"
    config.cache_timeout = 3600
    config.disable_content_trust = True
    config.cafile = None
    return config


def test_store_init(mocker, mock_config):
    """Tests that Store.__init__ initializes correctly."""
    mocker.patch("concil.store.DockerHub")
    mocker.patch(
        "concil.store.complete_url_with_auth",
        return_value=store.parse_docker_url("docker://docker.io/library/alpine:latest"),
    )
    mocker.patch(
        "concil.store.get_full_url",
        return_value="https://registry.hub.docker.com/v2/library/alpine",
    )
    mocker.patch("getpass.getpass", return_value="password")
    mocker.patch("builtins.input", return_value="user")

    s = store.Store("docker://docker.io/library/alpine:latest", config=mock_config)

    store.DockerHub.assert_called_once_with(
        "https://registry.hub.docker.com/v2/library/alpine", verify=None
    )
    assert s._hub is not None


def test_store_get_manifest_no_trust(mocker, mock_config):
    """Tests get_manifest with content trust disabled."""
    mocker.patch("concil.store.DockerHub")
    mocker.patch(
        "concil.store.complete_url_with_auth",
        return_value=store.parse_docker_url("docker://docker.io/library/alpine:latest"),
    )
    mocker.patch(
        "concil.store.get_full_url",
        return_value="https://registry.hub.docker.com/v2/library/alpine",
    )
    mock_hub = store.DockerHub.return_value
    mock_hub.get_manifest.return_value = (
        b'{"mediaType": "application/vnd.docker.distribution.manifest.v2+json"}'
    )

    s = store.Store("docker://docker.io/library/alpine:latest", config=mock_config)
    manifest = s.get_manifest()

    mock_hub.get_manifest.assert_called_once_with(
        accept="application/vnd.docker.distribution.manifest.v2+json"
    )
    assert (
        manifest["mediaType"] == "application/vnd.docker.distribution.manifest.v2+json"
    )


def test_store_get_manifest_with_cosign(mocker, mock_config):
    """Tests get_manifest with cosign content trust."""
    mock_config.disable_content_trust = False
    mock_config.content_trust = "cosign"
    mocker.patch("concil.store.DockerHub")
    mock_cosign_class = mocker.patch("concil.cosign.Cosign")
    mocker.patch(
        "concil.store.complete_url_with_auth",
        return_value=store.parse_docker_url("docker://docker.io/library/alpine:latest"),
    )
    mocker.patch(
        "concil.store.get_full_url",
        return_value="https://registry.hub.docker.com/v2/library/alpine",
    )
    mocker.patch("getpass.getpass", return_value="password")
    mocker.patch("builtins.input", return_value="user")
    mock_hub = store.DockerHub.return_value
    mock_hub.get_manifest.return_value = (
        b'{"mediaType": "application/vnd.docker.distribution.manifest.v2+json"}'
    )
    mock_cosign = mock_cosign_class.return_value

    s = store.Store("docker://docker.io/library/alpine:latest", config=mock_config)
    s.get_manifest()

    mock_cosign.check_signature.assert_called_once()


def test_store_get_manifest_with_notary(mocker, mock_config):
    """Tests get_manifest with notary content trust."""
    mock_config.disable_content_trust = False
    mock_config.content_trust = "notary"
    mocker.patch("concil.store.DockerHub")
    mocker.patch("concil.notary.Notary.__init__", return_value=None)
    mock_notary_class = mocker.patch("concil.notary.Notary")
    mocker.patch("concil.store.check_hashes", return_value=True)
    mocker.patch(
        "concil.store.complete_url_with_auth",
        return_value=store.parse_docker_url("docker://docker.io/library/alpine:latest"),
    )
    mocker.patch(
        "concil.store.get_full_url",
        return_value="https://registry.hub.docker.com/v2/library/alpine",
    )
    mocker.patch(
        "concil.store.get_notary_url",
        return_value="https://notary.docker.io/library/alpine",
    )
    mocker.patch("getpass.getpass", return_value="password")
    mocker.patch("builtins.input", return_value="user")

    mock_hub = store.DockerHub.return_value
    mock_notary = mock_notary_class.return_value
    mock_notary.get_digest_for_tag.return_value = ("sha256:digest", {"hashes": {}})

    s = store.Store("docker://docker.io/library/alpine:latest", config=mock_config)
    s._notary = mock_notary
    mocker.patch.object(s, "get_cache", side_effect=FileNotFoundError)
    mocker.patch.object(s, "store_cache")
    mock_hub.get_manifest.return_value = (
        b'{"mediaType": "application/vnd.docker.distribution.manifest.v2+json"}'
    )

    s.get_manifest()

    mock_notary.get_digest_for_tag.assert_called_once_with("latest")
    mock_hub.get_manifest.assert_called_once_with(hash="sha256:digest", accept=None)
    s.store_cache.assert_called_once()
