import platform
from hashlib import sha256

DIRECTORY_TRANSPORT = "Directory Transport Version: 1.1\n"
MANIFEST_DOCKER_MEDIA_TYPE = "application/vnd.docker.distribution.manifest.v2+json"
MANIFEST_OCI_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
MEDIA_TYPES = {
    MANIFEST_OCI_MEDIA_TYPE: {
        "config": "application/vnd.oci.image.config.v1+json",
        "tar": "application/vnd.oci.image.layer.v1.tar",
        "tar+gzip": "application/vnd.oci.image.layer.v1.tar+gzip",
        "tar+zstd": "application/vnd.oci.image.layer.v1.tar+zstd",
        "tar+encrypted": "application/vnd.oci.image.layer.v1.tar+encrypted",
        "tar+gzip+encrypted": "application/vnd.oci.image.layer.v1.tar+gzip+encrypted",
        "tar+zstd+encrypted": "application/vnd.oci.image.layer.v1.tar+zstd+encrypted",
        "squashfs": "application/vnd.oci.image.layer.v1.squashfs",
        "squashfs+encrypted": "application/vnd.oci.image.layer.v1.squashfs+encrypted",
    },
    MANIFEST_DOCKER_MEDIA_TYPE: {
        "config": "application/vnd.docker.container.image.v1+json",
        "tar": "application/vnd.docker.image.rootfs.diff.tar",
        "tar+gzip": "application/vnd.docker.image.rootfs.diff.tar.gzip",
        "tar+zstd": "application/vnd.docker.image.rootfs.diff.tar.zstd",
        "tar+encrypted": "application/vnd.docker.image.rootfs.diff.tar+encrypted",
        "tar+gzip+encrypted": "application/vnd.docker.image.rootfs.diff.tar.gzip+encrypted",
        "tar+zstd+encrypted": "application/vnd.docker.image.rootfs.diff.tar.zstd+encrypted",
        "squashfs": "application/vnd.docker.image.rootfs.diff.squashfs",
        "squashfs+encrypted": "application/vnd.docker.image.rootfs.diff.squashfs+encrypted",
    },
}
REVERSED_MEDIA_TYPES = {
    key: value for types in MEDIA_TYPES.values() for value, key in types.items()
}

PLATFORMS_TO_ARCHITECTURE = {
    "x86_64": "amd64",
}


def current_architecture():
    return PLATFORMS_TO_ARCHITECTURE[platform.machine()]


class Descriptor:
    def __init__(self, media_type, size, digest, annotations=None):
        self.media_type = media_type
        self.size = size
        self.digest = digest
        self.annotations = annotations

    @classmethod
    def from_data(cls, data, media_type, annotations=None):
        hash = sha256(data).hexdigest()
        digest = f"sha256:{hash}"
        result = cls(media_type, len(data), digest, annotations)
        return result


def descriptor_to_dict(descriptor, manifest_format=MANIFEST_OCI_MEDIA_TYPE):
    media_type = descriptor.media_type
    result = {
        "mediaType": MEDIA_TYPES[manifest_format].get(media_type, media_type),
        "size": descriptor.size,
        "digest": descriptor.digest,
    }
    if descriptor.annotations:
        result["annotations"] = descriptor.annotations
    return result


def manifest_to_dict(config, layers, manifest_format=MANIFEST_OCI_MEDIA_TYPE):
    manifest = {
        "schemaVersion": 2,
    }
    if manifest_format != MANIFEST_OCI_MEDIA_TYPE:
        manifest["mediaType"] = manifest_format
    manifest["config"] = descriptor_to_dict(config, manifest_format)
    manifest["layers"] = [
        descriptor_to_dict(layer, manifest_format) for layer in layers
    ]
    return manifest
