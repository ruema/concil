# Store Module (`concil.store`)

The `concil.store` module acts as a high-level interface for fetching, caching, and managing container images from OCI-compliant registries. It integrates various functionalities like configuration management, registry interaction (via `concil.dockerhub`), content trust (via `concil.notary` or `concil.cosign`), and local caching with on-the-fly layer conversion.

## Core Functionalities

-   **Configuration Management:** Loads and provides access to `concil`'s global configuration.
-   **Registry Interaction:** Abstracts communication with remote registries for pulling manifests and blobs.
-   **Content Trust Integration:** Optionally verifies image signatures using Notary or Cosign before considering an image trusted.
-   **Local Caching:** Manages a local cache for manifests, configuration blobs, and layers to speed up access and reduce network usage. Includes cache cleanup logic.
-   **Layer Format Conversion:** Can convert image layers from their registry format (e.g., tar, tar+gzip) to squashfs, which is preferred by Concil's runtime.

## `ConcilConfig` Class

This class handles `concil`'s configuration, typically loaded from `~/.concil/config.json`.

-   **`__init__(self, config_path=None)`:**
    *   Loads configuration from `config_path` or the path specified by the `CONCIL_CONFIG` environment variable, falling back to `~/.concil/config.json`. If the file doesn't exist, it uses default `CONFIG_PARAMS`.
-   **Key Properties:**
    *   `cafile`: Path to a custom CA certificate bundle for HTTPS connections.
    *   `disable_content_trust` (bool): If `True`, disables Notary/Cosign checks.
    *   `cache_dir` (Path): Path to the local cache directory (default `~/.concil`).
    *   `cache_timeout` (int): Cache retention period in seconds.
    *   `content_trust` (str): Specifies the content trust system to use ("notary" or "cosign").
    *   `cosign_path` (Path): Directory for Cosign keys.
    *   `notary_path` (Path): Directory for Notary cache/keys.
    *   `notary_trust_pinning` (dict): Configuration for Notary trust pinning.
-   **`get_server_info(self, hostname)`:** Returns specific registry and Notary URLs for a given `hostname` if defined in the `remote_servers` section of the config.
-   **Authentication:** The configuration can store authentication details for registries in an `auths` dictionary, mapping repository URLs (or hostnames) to base64 encoded "username:password" strings. `complete_url_with_auth` (helper function) uses this to augment URLs.

## Layer Conversion Utilities

-   **`TAR2SQFS` (list):** Defines the command and default arguments for the external `tar2sqfs` utility (e.g., `["path/to/tar2sqfs", "-c", "zstd", "-X", "level=10"]`).
-   **`_convert_tar_to_squash(stream, output_filename)`:** Pipes a tar `stream` to the `tar2sqfs` subprocess to create a squashfs file at `output_filename`. Returns the SHA256 digest of the input tar stream.
-   **`convert_tar_gzip(stream, output_filename)`:** Wraps the input `stream` with `GzipFile` for decompression before passing it to `_convert_tar_to_squash`.
-   **`convert_tar(stream, output_filename)`:** Directly calls `_convert_tar_to_squash`.
-   **`IMAGE_CONVERTERS` (dict):** Maps OCI/Docker layer media types (like `application/vnd.oci.image.layer.v1.tar+gzip`) to their corresponding conversion functions (e.g., `convert_tar_gzip`).

## `Store` Class

The primary class for managing image access.

-   **`__init__(self, url, config=None, verify=None)`:**
    *   `url` (str): The `docker://` URL of the image.
    *   `config` (`ConcilConfig`, optional): An instance of `ConcilConfig`. If `None`, a new one is created.
    *   `verify` (str, optional): Path to CA bundle, overriding config.
    *   Parses the `url`.
    *   Completes the URL with authentication details using `complete_url_with_auth` and `get_full_url`.
    *   Initializes a `DockerHub` client (`self._hub`) for registry communication.
    *   Based on `config.content_trust` and `config.disable_content_trust`, initializes:
        *   `self._cosign` (a `concil.cosign.Cosign` instance) or
        *   `self._notary` (a `concil.notary.Notary` instance). The Notary client is configured with its own trust directory and pinning settings from `ConcilConfig`.

-   **Caching Methods:**
    *   `cache_cleanup(self)`: Iterates through cache subdirectories (`manifest`, `config`, `layers`) and removes files older than `self._cache_timeout`.
    *   `store_cache(self, type, bytes, digest=None)`: Writes `bytes` to the cache in the appropriate `type` subdirectory, named by its `digest`.
    *   `get_cache(self, type, digest)`: Reads and returns bytes from the cache if the entry exists. Updates file access time.

-   **Image Component Retrieval:**
    *   **`get_manifest(self, architecture=None, operating_system=None)`:**
        1.  **Content Trust (Notary):** If Notary is enabled, calls `self._notary.get_digest_for_tag(self.url.tag)` to get the trusted manifest digest for the tag.
        2.  **Cache Check:** Tries to `get_cache("manifest", hex_digest_from_notary_or_tag)`.
        3.  **Download (if not cached or no Notary):** Calls `self._hub.get_manifest()`. If Notary provided a digest, fetches by that digest; otherwise, fetches by tag.
        4.  **Hash Verification (Notary):** If Notary was used, verifies the downloaded manifest against the hashes provided by Notary.
        5.  **Cache Store:** Stores the downloaded manifest.
        6.  **Content Trust (Cosign):** If Cosign is enabled, calls `self._cosign.check_signature(manifest_bytes)`.
        7.  **Manifest List Handling:** If the fetched manifest is a manifest list, it iterates through its `manifests` array to find an entry matching the target `architecture` and `operating_system`. It then calls `self._get_blob("manifest", entry_from_list)` to fetch the actual image manifest.
        8.  Returns the parsed JSON of the final image manifest.

    *   **`_get_blob(self, type, entry)`:** Generic internal method to fetch and cache any blob (manifest, config, layer).
        1.  `type` (str): "manifest", "config", or "layers".
        2.  `entry` (dict): A descriptor-like dictionary containing `digest` and `mediaType` (and optionally `size`).
        3.  **Cache Check:** Tries to `get_cache(type, entry['digest'])`. If found, returns the resolved path.
        4.  **Download (if not cached):**
            *   Creates a temporary output file (`<digest>.out`).
            *   Uses `self._hub.open_manifest()` or `self._hub.open_blob()` to stream the download into the temp file, calculating SHA256 on the fly.
            *   Verifies the downloaded size and calculated digest against `entry['size']` and `entry['digest']`.
        5.  **Layer Conversion:** If the `entry['mediaType']` is in `IMAGE_CONVERTERS` (e.g., it's a tarball):
            *   A target squashfs filename (`<digest_of_tar>.sq`) is prepared.
            *   The conversion function (e.g., `convert_tar_gzip`) is called with the downloaded tarball stream and the squashfs filename. This saves the converted layer.
            *   The original downloaded tarball (`.out` file) is then renamed to this squashfs filename (`<digest_of_tar>.sq`). The `diff_digest` (digest of the original tar) is used to create another cache entry if needed.
        6.  **Final Rename & Symlink:** The successfully downloaded/converted file is renamed to its final cache path (based on its primary digest). If conversion occurred, a symlink might be created from the original layer digest name to the converted file's name.
        7.  Handles `FileExistsError` during temp file creation to manage concurrent downloads of the same blob by different processes/threads.
        8.  Returns the `Path` object to the cached file.

    *   **`get_config(self, entry)`:** Calls `self._get_blob("config", entry)` and loads the JSON content.
    *   **`get_layer(self, entry)`:** Calls `self._get_blob("layers", entry)` to get the path to the (possibly converted) layer file.

## Helper Functions

-   **`unsplit_url(scheme, netloc, path=None, username=None, password=None, port=None)`:** Reconstructs a URL string from its components.
-   **`complete_url_with_auth(url, config)`:** Takes a parsed URL and a `ConcilConfig` object, and if auth information for the URL's repository/hostname is found in the config, it prepends "user:pass@" to the netloc.
-   **`get_full_url(url, config)`:** Resolves the full registry API URL based on `ConcilConfig`'s `remote_servers` or defaults.
-   **`get_notary_url(url, config)`:** Resolves the full Notary server URL based on `ConcilConfig`.

The `Store` module is a central piece of `concil` that brings together configuration, registry access, content trust, and caching to provide a robust way to obtain and manage container image components.
