import json
from pathlib import Path
from unittest.mock import ANY, MagicMock

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from concil import cosign, oci_spec


def test_generate_signing_blob():
    """Tests that generate_signing_blob creates the correct JSON blob."""
    blob = cosign.generate_signing_blob("my-repo", "my-digest")
    data = json.loads(blob)
    assert data["critical"]["identity"]["docker-reference"] == "my-repo"
    assert data["critical"]["image"]["docker-manifest-digest"] == "sha256:my-digest"
    assert data["critical"]["type"] == "cosign container image signature"


def test_generate_signing_config():
    """Tests that generate_signing_config creates the correct JSON blob."""
    blob = cosign.generate_signing_config("my-digest")
    data = json.loads(blob)
    assert data["rootfs"]["diff_ids"] == ["my-digest"]
    assert "created" in data


def test_sign_blob(mocker):
    """Tests that sign_blob correctly signs a blob."""
    mock_private_key = mocker.MagicMock()
    mock_private_key.sign.return_value = b"signature"
    mocker.patch("concil.cosign.load_pem_private_key", return_value=mock_private_key)
    mocker.patch("pathlib.Path.read_bytes", return_value=b"key_data")

    signature = cosign.sign_blob("my_key.pem", b"my-blob")
    assert signature == "c2lnbmF0dXJl"  # base64 encoded "signature"
    mock_private_key.sign.assert_called_once_with(b"my-blob", ANY)


def test_verify_blob(mocker):
    """Tests that verify_blob correctly verifies a signature."""
    mock_public_key = mocker.MagicMock()
    mocker.patch("concil.cosign.load_pem_public_key", return_value=mock_public_key)
    mocker.patch("pathlib.Path.read_bytes", return_value=b"key_data")

    # Test valid signature
    assert cosign.verify_blob(Path("my_key.pub"), b"my-blob", b"signature") is True
    mock_public_key.verify.assert_called_once_with(b"signature", b"my-blob", ANY)

    # Test invalid signature
    from cryptography.exceptions import InvalidSignature

    mock_public_key.verify.side_effect = InvalidSignature
    assert (
        cosign.verify_blob(Path("my_key.pub"), b"my-blob", b"invalid-signature")
        is False
    )


@pytest.fixture
def mock_hub():
    """A pytest fixture that returns a mock DockerHub instance."""
    hub = MagicMock()
    hub.repository = "my-repo"
    hub.has_blob.return_value = True
    return hub


def test_cosign_publish(mocker, mock_hub):
    """Tests that Cosign.publish correctly publishes a signature."""
    mocker.patch("concil.cosign.generate_signing_blob", return_value=b"signing_blob")
    mocker.patch("concil.cosign.sign_blob", return_value="signature")
    mocker.patch("concil.cosign.generate_signing_config", return_value=b"config_blob")
    mocker.patch(
        "concil.oci_spec.Descriptor.from_data",
        side_effect=[
            oci_spec.Descriptor(media_type="mt1", size=1, digest="signing_digest"),
            oci_spec.Descriptor(media_type="mt2", size=2, digest="config_digest"),
        ],
    )
    mocker.patch("concil.oci_spec.manifest_to_dict", return_value={"a": "b"})
    mocker.patch("json.dumps", return_value="manifest_json")

    cs = cosign.Cosign(mock_hub)
    cs.publish("my-manifest-digest", "my-key")

    cosign.generate_signing_blob.assert_called_once_with(
        "my-repo", "my-manifest-digest"
    )
    cosign.sign_blob.assert_called_once_with("my-key", b"signing_blob")
    cosign.generate_signing_config.assert_called_once_with("signing_digest")
    mock_hub.post_manifest.assert_called_once_with(
        b"manifest_json",
        tag="sha256-my-manifest-digest.sig",
        content_type="application/vnd.oci.image.manifest.v1+json",
    )
