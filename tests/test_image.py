import pytest
from unittest.mock import MagicMock
from pathlib import Path
from concil import image


def test_encode_base64():
    """Tests that encode_base64 encodes correctly."""
    assert image.encode_base64(b"test") == "dGVzdA=="


def test_calculate_digest(mocker):
    """Tests that calculate_digest calculates the correct digest."""
    mock_file = mocker.mock_open(read_data=b"some data")
    mocker.patch("pathlib.Path.open", mock_file)
    digest = image.calculate_digest(Path("anyfile"))
    expected_digest = "sha256:1307990e6ba5ca145eb35e99182a9bec46531bc54ddf656a602c780fa0240dee"
    assert digest == expected_digest


@pytest.fixture
def mock_layer_descriptor(mocker):
    """A pytest fixture for a LayerDescriptor instance."""
    mocker.patch("pathlib.Path.stat")
    return image.LayerDescriptor(
        filename=Path("/tmp/layer"),
        media_type="application/vnd.oci.image.layer.v1.tar+gzip",
        digest="sha256:abcdef",
        size=123,
    )


def test_layer_descriptor_init(mock_layer_descriptor):
    """Tests LayerDescriptor initialization."""
    assert mock_layer_descriptor.filename == Path("/tmp/layer")
    assert mock_layer_descriptor.size == 123


def test_layer_descriptor_from_data():
    """Tests LayerDescriptor.from_data."""
    data = b"layer data"
    descriptor = image.LayerDescriptor.from_data(data, "my-media-type")
    assert descriptor.size == len(data)
    assert descriptor.data is data


def test_image_manifest_init():
    """Tests ImageManifest initialization."""
    manifest = image.ImageManifest("/tmp/image")
    assert manifest.path == "/tmp/image"
