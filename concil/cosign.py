import base64
import datetime
import hashlib
import json
import logging
from pathlib import Path

import requests.exceptions
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

from . import oci_spec

logger = logging.getLogger(__file__)


def generate_signing_blob(reference, manifest_digest):
    """Generates the simple signing JSON blob.

    Args:
        reference (str): The Docker reference for the image.
        manifest_digest (str): The digest of the image manifest.

    Returns:
        bytes: The JSON-encoded simple signing blob.
    """
    simplesigning = {
        "critical": {
            "identity": {"docker-reference": reference},
            "image": {"docker-manifest-digest": "sha256:%s" % manifest_digest},
            "type": "cosign container image signature",
        },
        "optional": None,
    }
    return json.dumps(simplesigning).encode("utf8")


def generate_signing_config(simplesigning_digest):
    """Generates the signing configuration JSON blob.

    Args:
        simplesigning_digest (str): The digest of the simple signing blob.

    Returns:
        bytes: The JSON-encoded signing configuration blob.
    """
    utcnow = datetime.datetime.utcnow().isoformat() + "Z"
    config = {
        "architecture": "",
        "created": utcnow,
        "history": [{"created": "0001-01-01T00:00:00Z"}],
        "os": "",
        "rootfs": {"type": "layers", "diff_ids": [simplesigning_digest]},
        "config": {},
    }
    return json.dumps(config).encode("utf8")


def sign_blob(private_key, blob, password=None):
    """Signs a blob with a private key.

    Args:
        private_key (str or Path): The path to the private key file.
        blob (bytes): The blob to sign.
        password (bytes, optional): The password for the private key. If not
            provided, it will be prompted for. Defaults to None.

    Returns:
        str: The base64-encoded signature.
    """
    try:
        sk = load_pem_private_key(Path(private_key).read_bytes(), password)
    except TypeError:
        import getpass

        password = getpass.getpass("Password for key %s:" % private_key).encode("utf8")
        sk = load_pem_private_key(Path(private_key).read_bytes(), password)
    sig = sk.sign(blob, ec.ECDSA(hashes.SHA256()))
    return base64.standard_b64encode(sig).decode("ASCII")


def verify_blob(keyfile, blob, signature):
    """Verifies a signature for a blob.

    Args:
        keyfile (Path): The path to the public key file.
        blob (bytes): The blob that was signed.
        signature (bytes): The signature to verify.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    vk = load_pem_public_key(keyfile.read_bytes(), backend=default_backend())
    try:
        vk.verify(signature, blob, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


class Cosign:
    """A client for interacting with Cosign."""

    def __init__(self, hub, config={}):
        """Initializes a Cosign client.

        Args:
            hub (DockerHub): The DockerHub client to use for communication.
            config (dict, optional): A configuration dictionary. Defaults to {}.
        """
        self._hub = hub
        self._config = config

    def publish(self, manifest_digest, private_key):
        """Publishes a signature for a manifest.

        Args:
            manifest_digest (str): The digest of the manifest to sign.
            private_key (str or Path): The path to the private key to use for
                signing.
        """
        directory = self._config.get("key_dir")
        if directory:
            path = Path(directory) / f"{private_key}.key"
            if path.is_file():
                private_key = path
        simplesigning_blob = generate_signing_blob(
            self._hub.repository, manifest_digest
        )
        new_signature = sign_blob(private_key, simplesigning_blob)
        layer = oci_spec.Descriptor.from_data(
            simplesigning_blob,
            "application/vnd.dev.cosign.simplesigning.v1+json",
            annotations={"dev.cosignproject.cosign/signature": new_signature},
        )
        config_blob = generate_signing_config(layer.digest)
        config = oci_spec.Descriptor.from_data(config_blob, "config")
        manifest = oci_spec.manifest_to_dict(config, layers=[layer])
        hub = self._hub
        if hub.has_blob(layer.digest):
            print(f"Blob {layer.digest} found.")
        else:
            print(f"Blob {layer.digest} uploading...")
            hub.post_blob_data(simplesigning_blob, layer.digest)
            print("finished.")

        if hub.has_blob(config.digest):
            print(f"Blob {config.digest} found.")
        else:
            print(f"Blob {config.digest} uploading...")
            hub.post_blob_data(config_blob, config.digest)
            print("finished.")

        print("Writing manifest to image destination.")
        data = json.dumps(manifest).encode()
        try:
            hub.post_manifest(
                data,
                tag="sha256-%s.sig" % manifest_digest,
                content_type="application/vnd.oci.image.manifest.v1+json",
            )
        except requests.exceptions.HTTPError as err:
            print(err.response.headers)
            print(err.response.content)
            raise

    def check_signature(self, manifest_bytes):
        """Checks the signature for a manifest.

        Args:
            manifest_bytes (bytes): The manifest to check the signature for.

        Raises:
            ValueError: If the image is not signed, no signing key is found,
                or the signature verification fails.
        """
        hashsum256 = "sha256-%s.sig" % hashlib.sha256(manifest_bytes).hexdigest()
        try:
            signature_manifest_bytes = self._hub.get_manifest(
                hash=hashsum256,
                accept="application/vnd.docker.distribution.manifest.v1+json,application/vnd.docker.distribution.manifest.v1+prettyjws,application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.index.v1+json",
            )
        except requests.exceptions.HTTPError as err:
            if err.args[0].startswith("404"):
                raise ValueError("image is not signed")
            raise
        manifest = json.loads(signature_manifest_bytes)
        digest = manifest["layers"][-1]["digest"]
        signature = manifest["layers"][-1]["annotations"][
            "dev.cosignproject.cosign/signature"
        ]
        signature = base64.standard_b64decode(signature)
        blob = self._hub.open_blob(digest).content
        directory = self._config.get("key_dir")
        if directory and Path(directory).is_dir():
            for keyfile in Path(directory).glob("*.pub"):
                try:
                    logger.info("trying key %s", keyfile)
                    if verify_blob(keyfile, blob, signature):
                        return
                except Exception as e:
                    logger.debug(str(e))
        else:
            raise ValueError("no signing key found")
        raise ValueError("signature verify failed")
