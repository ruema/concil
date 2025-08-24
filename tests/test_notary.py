import json
import hashlib
from unittest.mock import MagicMock

import pytest
from concil import notary
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def test_encode_json():
    """Tests that encode_json produces canonical JSON."""
    data = {"b": 2, "a": 1}
    assert notary.encode_json(data) == b'{"a":1,"b":2}'


def test_generate_and_check_hashes():
    """Tests that generate_hashes and check_hashes work correctly."""
    data = b"some data"
    hashes = notary.generate_hashes(data)
    assert "sha256" in hashes["hashes"]
    assert "sha512" in hashes["hashes"]
    assert hashes["length"] == len(data)
    assert notary.check_hashes(data, hashes) is True
    assert notary.check_hashes(b"other data", hashes) is False


def test_generate_key_dict(mocker):
    """Tests that generate_key_dict creates a correct key dictionary."""
    mock_public_key = mocker.MagicMock()
    mock_public_key.public_bytes.return_value = b"public_bytes"
    mocker.patch("hashlib.sha256")
    hashlib.sha256.return_value.hexdigest.return_value = "key_id"

    key_dict, key_id = notary.generate_key_dict(mock_public_key)
    assert key_id == "key_id"
    assert key_dict["keytype"] == "ecdsa"
    assert key_dict["keyval"]["public"] == "cHVibGljX2J5dGVz"  # base64 of public_bytes


@pytest.fixture
def private_key():
    """A pytest fixture that returns an ECDSA private key."""
    return ec.generate_private_key(ec.SECP256R1())


def test_metafile_init():
    """Tests Metafile initialization."""
    meta = notary.Metafile(b'{"signed": {"version": 1, "expires": "2099-01-01T00:00:00Z"}, "signatures": []}')
    assert meta.version() == 1
    assert meta.dirty is False

    meta = notary.Metafile()
    assert meta.dirty is True


def test_root_metafile(private_key):
    """Tests the Root metafile class."""
    root = notary.Root()
    assert root.dirty is True
    key_dict, key_id = notary.generate_key_dict(private_key.public_key())
    root.add_key(key_id, key_dict, "root")
    assert key_id in root.get_keys("root")

    # test to_bytes
    root.to_bytes({key_id: private_key})
    assert root.dirty is True  # still dirty until saved
    data = json.loads(root.bytes)
    assert "signatures" in data
    assert len(data["signatures"]) == 1
