# Cosign Module (`concil.cosign`)

The `concil.cosign` module is responsible for handling [Cosign](https://github.com/sigstore/cosign) style signing and verification of container images. This ensures the integrity and authenticity of images.

## Core Functionality

The module provides mechanisms to:

- Generate a "simple signing" JSON blob that contains metadata about the image being signed (repository and manifest digest).
- Create an OCI-compliant manifest for the signature itself, which includes the simple signing blob as a layer.
- Sign the simple signing blob using an ECDSA private key.
- Verify a signature against a public key.
- Publish Cosign signatures to an OCI registry.
- Check for existing Cosign signatures on an image in a registry.

## Key Functions and Classes

### `generate_signing_blob(reference, manifest_digest)`

- **Purpose:** Creates the JSON blob that will be signed. This blob follows Cosign's "simple signing" format.
- **Arguments:**
    - `reference` (str): The Docker reference for the image (e.g., `docker.io/library/alpine`).
    - `manifest_digest` (str): The SHA256 digest of the image manifest being signed (without the `sha256:` prefix).
- **Returns:** A `bytes` object representing the JSON blob.

### `generate_signing_config(simplesigning_digest)`

- **Purpose:** Creates the OCI image configuration JSON for the signature image itself. The "rootfs" of this configuration points to the digest of the simple signing blob.
- **Arguments:**
    - `simplesigning_digest` (str): The digest of the simple signing blob (output from `generate_signing_blob` after being stored as a layer).
- **Returns:** A `bytes` object representing the JSON configuration for the signature.

### `sign_blob(private_key_path, blob, password=None)`

- **Purpose:** Signs a given blob of data (typically the simple signing blob) using a private key.
- **Arguments:**
    - `private_key_path` (str or Path): Path to the PEM-encoded private key file.
    - `blob` (bytes): The data to be signed.
    - `password` (str, optional): The password to decrypt the private key, if it's encrypted. If not provided and the key is encrypted, it will prompt for a password.
- **Returns:** A base64 encoded string of the signature.

### `verify_blob(public_key_path, blob, signature)`

- **Purpose:** Verifies a signature against a given blob of data using a public key.
- **Arguments:**
    - `public_key_path` (Path): Path to the PEM-encoded public key file.
    - `blob` (bytes): The original data that was signed.
    - `signature` (bytes): The raw signature bytes (after base64 decoding).
- **Returns:** `True` if the signature is valid, `False` otherwise.

### `class Cosign`

This class orchestrates the process of publishing and verifying Cosign signatures.

#### `__init__(self, hub, config={})`

- **Purpose:** Initializes the `Cosign` object.
- **Arguments:**
    - `hub`: An instance of a registry interaction client (e.g., `DockerHub` from `concil.dockerhub`) used to communicate with the OCI registry.
    - `config` (dict, optional): A configuration dictionary. It can contain a `key_dir` entry, specifying a directory where public keys (`.pub`) are stored for verification, or private keys (`.key`) for signing if a full path isn't given to `publish`.

#### `publish(self, manifest_digest, private_key_name_or_path)`

- **Purpose:** Signs an image manifest and publishes the signature to the OCI registry.
- **Details:**
    1. Generates the simple signing blob using the image's manifest digest and repository name.
    2. Signs this blob using the specified private key. If `private_key_name_or_path` is a name (not a path), it attempts to load it from the `key_dir` specified in the config.
    3. Creates OCI descriptors for the simple signing blob (as a layer) and its configuration.
    4. Uploads these blobs to the registry if they don't already exist.
    5. Creates and uploads an OCI manifest for the signature. The tag for this signature manifest is typically `sha256-<image_manifest_digest>.sig`.
- **Arguments:**
    - `manifest_digest` (str): The SHA256 digest of the image manifest to be signed.
    - `private_key_name_or_path` (str or Path): The name of the key (to be found in `key_dir`) or the direct path to the private key file.

#### `check_signature(self, manifest_bytes)`

- **Purpose:** Checks if a valid Cosign signature exists for a given image manifest in the OCI registry.
- **Details:**
    1. Calculates the expected tag for the signature manifest (e.g., `sha256-<image_manifest_digest>.sig`).
    2. Fetches this signature manifest from the registry.
    3. Extracts the simple signing blob and the signature itself from the layers of the signature manifest.
    4. Attempts to verify the signature using public keys found in the `key_dir` (if specified in the config).
- **Arguments:**
    - `manifest_bytes` (bytes): The byte content of the image manifest for which to check the signature.
- **Raises:**
    - `ValueError`: If the image is not signed, if no signing keys are found for verification, or if the signature verification fails.
    - `requests.exceptions.HTTPError`: If there's an issue fetching the signature from the registry (e.g., 404 if not found).

## Usage Example (Conceptual)

```python
# Assuming 'hub' is an initialized DockerHub client
# and 'config' is a dictionary like {'key_dir': '/path/to/cosign/keys'}

from concil.cosign import Cosign
from concil.dockerhub import DockerHub # Example hub

# Initialize hub for a specific repository
my_hub = DockerHub("docker.io/myuser/myimage:latest")
cosign_handler = Cosign(my_hub, config={'key_dir': '~/.concil/cosign_keys'})

# To sign and publish a signature
image_manifest_content = b'{...}' # Actual manifest content
image_manifest_digest = "abcdef12345..." # Digest of image_manifest_content
cosign_handler.publish(image_manifest_digest, "my_signing_key_id") # Assumes 'my_signing_key_id.key' exists in key_dir

# To check a signature
try:
    cosign_handler.check_signature(image_manifest_content)
    print("Image signature is valid!")
except ValueError as e:
    print(f"Signature check failed: {e}")

```

This module plays a crucial role in securing the container supply chain by allowing users to verify that the images they are using have not been tamed with and originate from a trusted source.
