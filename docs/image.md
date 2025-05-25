# Image Module (`concil.image`)

The `concil.image` module is at the heart of `concil`'s image management capabilities. It defines how OCI-compliant container images and their layers are represented, manipulated, imported, and exported.

## Core Concepts

- **Layers (`LayerDescriptor`):** Individual components of an image, such_as file system changes, stored as tarballs (optionally gzipped or squashed) or even raw directories during creation. Layers can be encrypted.
- **Image Manifest (`ImageManifest`):** A JSON document that describes an image, including its configuration, a list of its layers, and annotations. `concil` supports OCI image manifest and Docker v2 schema 2 manifest formats.
- **Image Configuration:** A JSON document (referenced by the manifest) detailing image properties like environment variables, entrypoint, command, exposed ports, etc.

## Key Classes

### `class LayerDescriptor`

Represents a single layer within an OCI image. It encapsulates the layer's data, metadata, and operations.

**Key Attributes:**

- `filename` (Path or `DockerPath`): The path to the layer data on disk or a reference to a remote layer. Can be `None` if data is held in memory.
- `media_type` (str): The OCI media type of the layer (e.g., `application/vnd.oci.image.layer.v1.tar+gzip`, `application/vnd.oci.image.layer.v1.squashfs`, `application/vnd.oci.image.layer.v1.tar`, or custom types like `dir` for local directories before conversion). Can also indicate encryption (e.g., `...tar+gzip+encrypted`).
- `digest` (str): The digest of the layer (usually `sha256:...`). For a `dir` media type, it might be a `dir:<path>` identifier before conversion.
- `unpacked_digest` (str): The digest of the layer *after* any compression (like gzip) is removed. For uncompressed or squashfs layers, this is the same as `digest`.
- `size` (int): The size of the layer data in bytes.
- `annotations` (dict): Annotations associated with the layer, often used for encryption metadata.
- `converted_media_type` (str, optional): If set, indicates the target media type the layer should be converted to during export (e.g., from `dir` to `tar+gzip` or `squashfs`).
- `encryption_keys` (list): A list of JWK keys used to encrypt this layer.
- `status` (str): Used during image modification. Can be:
    - `'keep'`: Keep the layer as is.
    - `'remove'`: Remove the layer.
    - `'merge'`: Merge this layer with subsequent layers (specified in `merge_with`).
    - `'new'`: This is a newly added layer.
- `merge_with` (list of `LayerDescriptor`): Used when `status` is `'merge'`, specifies other layers to merge into this one.

**Key Methods:**

- `__init__(self, filename, media_type, digest, annotations=None, size=None)`: Constructor.
- `from_data(cls, data, media_type, annotations=None)`: Class method to create a `LayerDescriptor` from in-memory byte data.
- `convert(self, media_type)`: Sets `converted_media_type` to request a format conversion on export.
- `as_tar_stream(self)`: Returns a file-like object (stream) containing the layer's content as an uncompressed tar archive. Handles decompression (gzip) or tarring (for `dir` type) as needed.
- `export(self, path, merge_with=None)`: Exports the layer to the specified `path` (usually a subdirectory within an OCI image layout). This is a complex method that handles:
    - Linking or copying the layer if no conversion or encryption is needed.
    - Converting the layer to `converted_media_type` (e.g., `dir` -> `tar` -> `squashfs`).
    - Merging with other layers using `MergedTarStream`.
    - Encrypting the layer using AES-256-CTR with HMAC-SHA256 if `encryption_keys` are provided. Encryption metadata is stored in annotations according to OCI image encryption specs.
    - Returns a new `LayerDescriptor` instance pointing to the exported layer.
- `read(self)`: Reads and returns the raw byte content of the layer.

---

### `class ImageManifest`

Represents an OCI image manifest. It holds references to the image configuration and all its layers.

**Key Attributes:**

- `path` (Path or `DockerPath`): The base path for resolving layer and config blobs, either a local directory or a `DockerPath` for remote images.
- `manifest_format` (str): The media type of the manifest itself (e.g., `application/vnd.oci.image.manifest.v1+json`).
- `config` (`LayerDescriptor`): A `LayerDescriptor` for the image's configuration blob.
- `layers` (list of `LayerDescriptor`): A list of `LayerDescriptor` objects representing the image's layers.
- `annotations` (dict): Annotations from the manifest.

**Key Methods:**

- `__init__(self, path, manifest_format=None)`: Constructor.
- `from_path(cls, path_or_url)`: Class method to load an image manifest.
    - If `path_or_url` starts with `docker://`, it fetches the manifest from the specified registry URL using `concil.dockerhub.DockerHub`.
    - Otherwise, it assumes a local filesystem path and tries to load from `manifest.json` or `index.json` (following OCI Image Layout structure).
- `configuration` (property): Lazily loads, parses, and returns the image configuration JSON (from `self.config.read()`) as a dictionary.
- `export(self, target_path, manifest_format=None)`: Exports the entire image to the `target_path` in OCI Image Layout format.
    1. Creates the `target_path` directory.
    2. Iterates through `self.layers`:
        - If a layer's `status` is `'remove'`, it's skipped.
        - If `'merge'`, it calls `layer.export()` with `layer.merge_with`.
        - Otherwise, calls `layer.export()`.
        - Collects the `LayerDescriptor` objects for the newly exported layers.
    3. Updates the `rootfs.diff_ids` in the image configuration based on the digests of the actually exported/merged layers and any new layers.
    4. Exports the (potentially modified) configuration blob.
    5. Generates the final manifest dictionary using `oci_spec.manifest_to_dict()`.
    6. Writes the manifest to `target_path/manifest.json` and an OCI layout `version` file.
- `publish(self, docker_url, manifest_format=None, root_certificate=None, cosign_key=None)`: Publishes the image to a remote OCI registry specified by `docker_url`.
    1. Initializes a `concil.store.Store` object for the `docker_url` to access `DockerHub`, `Notary`, and `Cosign` clients.
    2. Uploads each layer and the configuration blob to the registry if they don't already exist, using `DockerHub.post_blob()`.
    3. Uploads the image manifest using `DockerHub.post_manifest()`.
    4. If `root_certificate` is provided (for Notary) and Notary is configured, it signs the manifest with Notary.
    5. If `cosign_key` is provided and Cosign is configured, it signs the manifest with Cosign.

## Helper Functions

- `calculate_digest(filename, unzip=False)`: Computes the `sha256:` digest of a file. If `unzip` is `True`, it decompressesthe file with gzip before digesting.
- `encrypt(input_stream, encrypted_filename)`: Encrypts data from `input_stream` and writes it to `encrypted_filename`. Returns OCI encryption-related metadata.

This module forms the core of `concil`'s image manipulation logic, bridging local storage, remote registries, and various image format conversions and operations.
