import pytest
import json
from hashlib import sha256

from concil.oci_spec import (
    Descriptor,
    descriptor_to_dict,
    manifest_to_dict,
    MANIFEST_OCI_MEDIA_TYPE,
    MANIFEST_DOCKER_MEDIA_TYPE,
    MEDIA_TYPES
)

# Fixtures
@pytest.fixture
def sample_data():
    return b"Hello, OCI!"

@pytest.fixture
def sample_digest(sample_data):
    return "sha256:" + sha256(sample_data).hexdigest()

@pytest.fixture
def sample_annotations():
    return {"org.example.annotation": "test_value"}

@pytest.fixture
def oci_descriptor(sample_data, sample_digest, sample_annotations):
    return Descriptor(
        media_type="application/vnd.oci.image.layer.v1.tar",
        size=len(sample_data),
        digest=sample_digest,
        annotations=sample_annotations.copy()
    )

@pytest.fixture
def config_descriptor_oci(sample_data, sample_digest):
    # Simulating a config blob
    config_content = {"os": "linux", "architecture": "amd64"}
    config_bytes = json.dumps(config_content).encode('utf-8')
    return Descriptor.from_data(
        config_bytes,
        MEDIA_TYPES[MANIFEST_OCI_MEDIA_TYPE]["config"]
    )

@pytest.fixture
def layer_descriptor_oci_1(sample_data, sample_digest):
    return Descriptor.from_data(
        sample_data,
        MEDIA_TYPES[MANIFEST_OCI_MEDIA_TYPE]["tar+gzip"],
        annotations={"layer": "1"}
    )

@pytest.fixture
def layer_descriptor_oci_2():
    other_data = b"Another layer"
    return Descriptor.from_data(
        other_data,
        MEDIA_TYPES[MANIFEST_OCI_MEDIA_TYPE]["tar"],
        annotations={"layer": "2"}
    )

# Tests for Descriptor class
def test_descriptor_creation(oci_descriptor, sample_data, sample_digest, sample_annotations):
    assert oci_descriptor.media_type == "application/vnd.oci.image.layer.v1.tar"
    assert oci_descriptor.size == len(sample_data)
    assert oci_descriptor.digest == sample_digest
    assert oci_descriptor.annotations == sample_annotations

def test_descriptor_from_data(sample_data, sample_digest):
    media_type = "application/vnd.custom.data"
    annotations = {"key": "value"}
    desc = Descriptor.from_data(sample_data, media_type, annotations.copy())

    assert desc.media_type == media_type
    assert desc.size == len(sample_data)
    assert desc.digest == sample_digest
    assert desc.annotations == annotations

def test_descriptor_from_data_no_annotations(sample_data, sample_digest):
    media_type = "application/vnd.custom.data"
    desc = Descriptor.from_data(sample_data, media_type)

    assert desc.media_type == media_type
    assert desc.size == len(sample_data)
    assert desc.digest == sample_digest
    assert desc.annotations is None # Or {} depending on implementation, current is None

# Tests for descriptor_to_dict
def test_descriptor_to_dict_oci(oci_descriptor, sample_digest, sample_annotations):
    desc_dict = descriptor_to_dict(oci_descriptor, MANIFEST_OCI_MEDIA_TYPE)
    assert desc_dict["mediaType"] == "application/vnd.oci.image.layer.v1.tar"
    assert desc_dict["size"] == oci_descriptor.size
    assert desc_dict["digest"] == sample_digest
    assert desc_dict["annotations"] == sample_annotations

def test_descriptor_to_dict_docker(oci_descriptor, sample_digest, sample_annotations):
    # Assuming 'oci_descriptor' uses an OCI media type that has a Docker equivalent
    # For "application/vnd.oci.image.layer.v1.tar" -> "application/vnd.docker.image.rootfs.diff.tar"
    desc_dict = descriptor_to_dict(oci_descriptor, MANIFEST_DOCKER_MEDIA_TYPE)
    expected_docker_media_type = MEDIA_TYPES[MANIFEST_DOCKER_MEDIA_TYPE].get(oci_descriptor.media_type)
    if expected_docker_media_type is None:
        # If direct mapping isn't there, it should use the original type
        expected_docker_media_type = oci_descriptor.media_type


    assert desc_dict["mediaType"] == expected_docker_media_type
    assert desc_dict["size"] == oci_descriptor.size
    assert desc_dict["digest"] == sample_digest
    assert desc_dict["annotations"] == sample_annotations

def test_descriptor_to_dict_no_annotations(sample_data, sample_digest):
    desc = Descriptor(
        media_type="application/vnd.oci.image.layer.v1.tar",
        size=len(sample_data),
        digest=sample_digest
        # No annotations
    )
    desc_dict = descriptor_to_dict(desc)
    assert "annotations" not in desc_dict

def test_descriptor_to_dict_unmapped_type_for_docker(sample_data, sample_digest):
    # Use a media type that only exists in OCI and not directly in the Docker map for 'tar'
    oci_specific_type = "application/vnd.oci.image.layer.v1.tar.custom"
    desc = Descriptor(
        media_type=oci_specific_type,
        size=len(sample_data),
        digest=sample_digest
    )
    desc_dict = descriptor_to_dict(desc, MANIFEST_DOCKER_MEDIA_TYPE)
    # It should retain its original media type if no mapping is found
    assert desc_dict["mediaType"] == oci_specific_type


# Tests for manifest_to_dict
def test_manifest_to_dict_oci(config_descriptor_oci, layer_descriptor_oci_1, layer_descriptor_oci_2):
    layers = [layer_descriptor_oci_1, layer_descriptor_oci_2]
    manifest = manifest_to_dict(config_descriptor_oci, layers, MANIFEST_OCI_MEDIA_TYPE)

    assert manifest["schemaVersion"] == 2
    assert manifest["mediaType"] == MANIFEST_OCI_MEDIA_TYPE # Default, so not explicitly set
    assert manifest["config"]["mediaType"] == MEDIA_TYPES[MANIFEST_OCI_MEDIA_TYPE]["config"]
    assert manifest["config"]["size"] == config_descriptor_oci.size
    assert manifest["config"]["digest"] == config_descriptor_oci.digest

    assert len(manifest["layers"]) == 2
    assert manifest["layers"][0]["mediaType"] == MEDIA_TYPES[MANIFEST_OCI_MEDIA_TYPE]["tar+gzip"]
    assert manifest["layers"][0]["size"] == layer_descriptor_oci_1.size
    assert manifest["layers"][0]["digest"] == layer_descriptor_oci_1.digest
    assert manifest["layers"][0]["annotations"] == {"layer": "1"}

    assert manifest["layers"][1]["mediaType"] == MEDIA_TYPES[MANIFEST_OCI_MEDIA_TYPE]["tar"]
    assert manifest["layers"][1]["size"] == layer_descriptor_oci_2.size
    assert manifest["layers"][1]["digest"] == layer_descriptor_oci_2.digest
    assert manifest["layers"][1]["annotations"] == {"layer": "2"}

def test_manifest_to_dict_docker(config_descriptor_oci, layer_descriptor_oci_1):
    # Create a config descriptor that would be typical for Docker
    config_content_docker = {"os": "windows", "architecture": "amd64"} # example
    config_bytes_docker = json.dumps(config_content_docker).encode('utf-8')
    config_descriptor_docker = Descriptor.from_data(
        config_bytes_docker,
        MEDIA_TYPES[MANIFEST_DOCKER_MEDIA_TYPE]["config"] # Explicitly Docker config type
    )

    # Create a layer descriptor that uses a Docker media type
    layer_data_docker = b"Docker layer content"
    layer_descriptor_docker = Descriptor.from_data(
        layer_data_docker,
        MEDIA_TYPES[MANIFEST_DOCKER_MEDIA_TYPE]["tar+gzip"] # Explicitly Docker layer type
    )

    layers = [layer_descriptor_docker]
    manifest = manifest_to_dict(config_descriptor_docker, layers, MANIFEST_DOCKER_MEDIA_TYPE)

    assert manifest["schemaVersion"] == 2
    assert manifest["mediaType"] == MANIFEST_DOCKER_MEDIA_TYPE # Explicitly set for Docker
    
    assert manifest["config"]["mediaType"] == MEDIA_TYPES[MANIFEST_DOCKER_MEDIA_TYPE]["config"]
    assert manifest["config"]["size"] == config_descriptor_docker.size
    assert manifest["config"]["digest"] == config_descriptor_docker.digest

    assert len(manifest["layers"]) == 1
    assert manifest["layers"][0]["mediaType"] == MEDIA_TYPES[MANIFEST_DOCKER_MEDIA_TYPE]["tar+gzip"]
    assert manifest["layers"][0]["size"] == layer_descriptor_docker.size
    assert manifest["layers"][0]["digest"] == layer_descriptor_docker.digest
    
def test_manifest_to_dict_oci_default_mediatype(config_descriptor_oci, layer_descriptor_oci_1):
    # Test that if manifest_format is MANIFEST_OCI_MEDIA_TYPE, the top-level mediaType is NOT set
    layers = [layer_descriptor_oci_1]
    manifest = manifest_to_dict(config_descriptor_oci, layers, MANIFEST_OCI_MEDIA_TYPE)
    assert "mediaType" not in manifest # OCI manifest type is default

    manifest_explicit_oci = manifest_to_dict(config_descriptor_oci, layers) # Default is OCI
    assert "mediaType" not in manifest_explicit_oci
