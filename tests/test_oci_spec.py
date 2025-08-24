import pytest
from concil import oci_spec


def test_descriptor_from_data():
    """Tests that Descriptor.from_data creates a correct descriptor."""
    data = b"some data"
    descriptor = oci_spec.Descriptor.from_data(data, "my-media-type")
    assert descriptor.size == len(data)
    assert descriptor.media_type == "my-media-type"
    expected_digest = "sha256:1307990e6ba5ca145eb35e99182a9bec46531bc54ddf656a602c780fa0240dee"
    assert descriptor.digest == expected_digest


def test_descriptor_to_dict():
    """Tests that descriptor_to_dict converts a descriptor to a dictionary."""
    descriptor = oci_spec.Descriptor(
        media_type="tar+gzip",
        size=123,
        digest="sha256:mydigest",
        annotations={"a": "b"},
    )
    d = oci_spec.descriptor_to_dict(descriptor)
    assert d["mediaType"] == "application/vnd.oci.image.layer.v1.tar+gzip"
    assert d["size"] == 123
    assert d["digest"] == "sha256:mydigest"
    assert d["annotations"] == {"a": "b"}

    d = oci_spec.descriptor_to_dict(descriptor, manifest_format=oci_spec.MANIFEST_DOCKER_MEDIA_TYPE)
    assert d["mediaType"] == "application/vnd.docker.image.rootfs.diff.tar.gzip"


def test_manifest_to_dict():
    """Tests that manifest_to_dict creates a correct manifest dictionary."""
    config = oci_spec.Descriptor("config", 1, "sha256:config")
    layer = oci_spec.Descriptor("tar", 2, "sha256:layer")
    manifest = oci_spec.manifest_to_dict(config, [layer])
    assert manifest["schemaVersion"] == 2
    assert manifest["config"]["digest"] == "sha256:config"
    assert len(manifest["layers"]) == 1
    assert manifest["layers"][0]["digest"] == "sha256:layer"
