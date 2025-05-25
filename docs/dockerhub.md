# DockerHub Client Module (`concil.dockerhub`)

The `concil.dockerhub` module provides a client for interacting with OCI-compliant container registries (such as Docker Hub, Harbor, etc.). It handles parsing registry URLs, authentication, and the OCI registry API calls for managing manifests and blobs (layers).

## Core Functionality

- Parse `docker://` scheme URLs to extract registry location, repository name, and tag.
- Manage authentication with the registry, including prompting for username/password if not provided and handling token-based authentication.
- Upload and download image layers (blobs).
- Upload and download image manifests.
- Check for the existence of blobs in the registry.

## Key Functions and Classes

### `parse_docker_url(docker_url)`

- **Purpose:** Parses a Docker URL string (e.g., `docker://docker.io/library/alpine:latest` or `docker://user:pass@myregistry.com:5000/myimage:tag`) into its constituent parts.
- **Arguments:**
    - `docker_url` (str): The Docker URL to parse.
- **Returns:** A `DockerSplitResult` object.

### `class DockerSplitResult`

A subclass of `urllib.parse.SplitResult` with additional properties tailored for Docker URLs:

- `repository` (str): The name of the repository (e.g., `library/alpine`).
- `tag` (str): The tag of the image (e.g., `latest`). Defaults to `latest` if not specified.
- `url` (str): The base HTTP(S) URL for accessing the registry's v2 API (e.g., `https://registry-1.docker.io/v2/library/alpine`).

### `class ResponseStream`

A wrapper around a `requests.Response` object to provide a file-like object for reading streaming content, particularly useful for downloading large blobs.

- `read(size=None)`: Reads data from the stream.
- `close()`: Closes the underlying response.
- Implements context manager protocol (`__enter__`, `__exit__`).

### `class DockerPath`

Represents a blob within a Docker registry, identified by its digest. It provides a way to treat remote blobs somewhat like local file paths.

- `__init__(self, hub, digest=None)`:
    - `hub`: An instance of the `DockerHub` class.
    - `digest` (str, optional): The digest of the blob (e.g., `sha256:abcdef...`).
- `read_bytes()`: Downloads and returns the entire content of the blob as bytes.
- `open(mode='rb')`: Returns a `ResponseStream` for reading the blob's content. Only `rb` mode is supported.

### `class DockerHub`

The main client class for interacting with a Docker/OCI registry.

#### `__init__(self, docker_url, verify=None)`

- **Purpose:** Initializes the DockerHub client.
- **Arguments:**
    - `docker_url` (str): The full Docker URL (e.g., `docker://user:password@hostname/repository:tag`).
    - `verify` (bool or str, optional): Path to CA bundle to use for SSL verification, or `False` to disable SSL verification. Defaults to `None` (uses system CAs).
- **Attributes:**
    - `username` (str): Username for authentication.
    - `password` (str): Password for authentication.
    - `repository` (str): Target repository name.
    - `url` (str): Base URL for the registry API.
    - `tag` (str): Target tag.
    - `session` (requests.Session): The session object used for making HTTP requests.

#### Authentication

Authentication is handled transparently. If a request returns a 401 (Unauthorized), the client attempts to authenticate using:
1. Credentials provided in the initial `docker_url`.
2. If not present, it prompts the user for username and password via `input()` and `getpass.getpass()`.
It then requests a token from the registry's authentication service and uses it for subsequent requests.

#### Methods

- `request(self, method, url, **kw)`: A wrapper around `self.session.request` that includes authentication handling.
- `post_blob(self, filename)`: Uploads a blob from a local file. The digest is derived from the filename (assuming it's `sha256:<digest>`).
    - **Deprecated behavior note:** The digest derivation from filename might be fragile. `post_blob_data` is generally preferred.
- `post_blob_data(self, data, digest)`: Uploads a blob from in-memory bytes.
    - `data` (bytes): The content of the blob.
    - `digest` (str): The full digest of the blob (e.g., `sha256:abcdef...`).
- `post_manifest(self, data, tag=None, content_type="application/vnd.docker.distribution.manifest.v2+json")`: Uploads an image manifest.
    - `data` (bytes): The manifest content.
    - `tag` (str, optional): The tag to assign to the manifest. Defaults to the tag from the initial `docker_url`.
    - `content_type` (str): The content type of the manifest.
- `open_blob(self, digest)`: Opens a stream to download a blob.
    - `digest` (str): The digest of the blob to download.
    - **Returns:** A `requests.Response` object in stream mode.
- `has_blob(self, digest)`: Checks if a blob exists in the registry.
    - `digest` (str): The digest of the blob.
    - **Returns:** `True` if the blob exists, `False` otherwise.
- `open_manifest(self, hash=None, accept="application/vnd.docker.distribution.manifest.v1+json")`: Opens a stream to download a manifest.
    - `hash` (str, optional): The digest or tag of the manifest. Defaults to the tag from the initial `docker_url`.
    - `accept` (str): The `Accept` header value specifying the desired manifest type(s).
    - **Returns:** A `requests.Response` object in stream mode.
- `get_manifest(self, hash=None, accept="application/vnd.docker.distribution.manifest.v1+json")`: Downloads a manifest and returns its content.
    - Parameters are the same as `open_manifest`.
    - **Returns:** `bytes` containing the manifest content.

## Usage Example

```python
from concil.dockerhub import DockerHub

# Initialize client for a specific image
# For public images, no credentials needed in URL
client = DockerHub("docker://docker.io/library/alpine:latest")

# Or for a private registry with credentials
# client = DockerHub("docker://user:secret@myregistry.com/myrepo:v1", verify="/path/to/ca.crt")

try:
    # Get the image manifest
    manifest_content = client.get_manifest(accept="application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json")
    print("Manifest downloaded.")

    # (Parse manifest_content to get layer digests)
    # Example: layer_digest = "sha256:actual_layer_digest_from_manifest"

    # Check if a blob exists
    # if client.has_blob(layer_digest):
    #    print(f"Blob {layer_digest} exists.")
    #    # Download a blob
    #    with client.open_blob(layer_digest) as blob_stream:
    #        with open("layer.tar.gz", "wb") as f_out:
    #            for chunk in blob_stream.iter_content(8192):
    #                f_out.write(chunk)
    #    print(f"Blob {layer_digest} downloaded to layer.tar.gz")

    # Uploading (conceptual - requires an actual blob and manifest)
    # dummy_blob_data = b"some layer data"
    # dummy_blob_digest = "sha256:" + hashlib.sha256(dummy_blob_data).hexdigest()
    # client.post_blob_data(dummy_blob_data, dummy_blob_digest)
    
    # dummy_manifest_data = b'{"schemaVersion": 2, ...}'
    # client.post_manifest(dummy_manifest_data, tag="mytag")

except requests.exceptions.HTTPError as e:
    print(f"HTTP Error: {e}")
except Exception as e:
    print(f"An error occurred: {e}")
```

This module is fundamental for `concil`'s ability to pull images from and push images to remote registries.
