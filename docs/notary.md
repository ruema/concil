# Notary Client Module (`concil.notary`)

The `concil.notary` module implements a client for interacting with a Notary v1 server, which is an implementation of [The Update Framework (TUF)](https://theupdateframework.io/). This module is responsible for managing cryptographic keys, fetching and verifying TUF metadata, and publishing signed metadata to ensure the authenticity and integrity of container images.

## Overview of TUF Roles

The module implements the client-side logic for the standard TUF roles:

-   **Root:** Establishes the root of trust. The `root.json` file contains public keys for all other top-level roles (Targets, Snapshot, Timestamp, and the Root role itself for key rotation) and defines the signing thresholds for each role.
-   **Targets:** Provides metadata about the available images/tags and their cryptographic hashes. The `targets.json` file lists available artifacts and can delegate trust to other signing keys for specific namespaces or collections of artifacts (delegations).
-   **Snapshot:** Provides a consistent view of all other metadata files in the repository (except for `timestamp.json`). The `snapshot.json` file lists the versions of `root.json`, `targets.json`, and any delegation `targets.json` files. This helps prevent mix-and-match attacks.
-   **Timestamp:** Provides freshness guarantees for the repository metadata. The `timestamp.json` file signs over the `snapshot.json` file, indicating that it's the latest available snapshot. This is usually the first file fetched by a client.

## Core Functionality

The `concil.notary` module enables `concil` to:

-   **Securely initialize trust:** When interacting with a new repository for the first time, it can establish a root of trust. This might involve fetching an initial `root.json` and potentially using trust pinning configurations.
-   **Fetch and verify TUF metadata:** It downloads TUF metadata files (timestamp, snapshot, root, targets, and delegation targets) from a Notary server. Each file's signature and integrity are cryptographically verified against trusted keys (e.g., root keys, delegate keys) according to TUF workflow. Expiration dates and versions are also checked.
-   **Manage cryptographic keys:** It interfaces with a `PrivateKeyStore` to handle local storage and use of private keys required for signing TUF metadata when publishing changes. Keys are typically encrypted on disk and require passphrases for use.
-   **Ensure metadata freshness and consistency:** By following the TUF update workflow (checking timestamp, then snapshot, then other files), it protects against freeze, rollback, and mix-and-match attacks.
-   **Publish signed metadata:** When changes are made to image tags under Concil's management (e.g., a new image is pushed and needs to be signed into Notary), this module can update `targets.json`, sign it, update `snapshot.json` and `timestamp.json` accordingly, and publish these changes to the Notary server.
-   **Handle key delegations:** It can interpret TUF delegations specified in `targets.json` files, allowing different keys to sign for different parts of the repository's metadata.
-   **Verify image digests against trusted metadata:** Before an image is considered trusted, `concil` can use this module to get the authoritative cryptographic hash for a specific image tag from the verified Notary `targets.json` metadata.
-   **Trust Pinning:** Supports `trust_pinning` configurations (often from `~/.notary/config.json` or a similar Concil config) to ensure that the fetched `root.json` aligns with pre-configured CA certificates or specific root key IDs for a given repository. This mitigates attacks involving a compromised Notary server or initial trust establishment.

## Key Classes and Their Responsibilities

### `class Notary`

This is the main public class for client interaction with a Notary server.

-   **`__init__(self, url, initialize=False, config=CONFIG_PATH, verify=None)`:**
    *   Initializes the Notary client for a specific repository URL (e.g., `docker.io/library/alpine`).
    *   `url`: The GUN (Globally Unique Name) for the repository.
    *   `initialize`: A boolean flag. If `True`, it might try to initialize roles if they don't exist (though client-side initialization is limited).
    *   `config`: Path to a Notary configuration file or a dictionary containing configuration parameters like `trust_dir` and `trust_pinning`. Defaults to `~/.notary/config.json`.
    *   `verify`: Path to a CA bundle for HTTPS connections.
    *   On initialization, it sets up a `JsonStore` for backend communication and a `PrivateKeyStore` for key access. It then attempts to load existing TUF metadata (timestamp, snapshot, root, targets) by following the TUF update process, ensuring each piece of metadata is valid and trusted.

-   **`add_target_hashes(self, target, hashes, role=None)`:**
    *   Adds or updates a target's hash information in the appropriate `targets.json` metadata (either the top-level targets or a delegated role's targets).
    *   `target`: The name of the target (e.g., an image tag like "latest").
    *   `hashes`: A dictionary containing hash algorithm names (e.g., "sha256") and their corresponding hex-encoded hash values for the target.
    *   Marks the relevant `Targets` object as dirty.

-   **`get_digest_for_tag(self, tag)`:**
    *   Retrieves the trusted digest (and other hash information) for a given image `tag` from the verified `targets.json` (or relevant delegation).
    *   This is a key method for clients to know the "correct" hash of an image tag according to Notary.

-   **`publish(self, root_certificate=None)`:**
    *   Orchestrates the signing and publishing of updated TUF metadata to the Notary server.
    *   It checks which metadata files (`Targets`, `Root`, `Snapshot`) are "dirty" (modified).
    *   It retrieves the necessary private keys from `PrivateKeyStore` (prompting for passphrases if needed) to sign these files.
        *   `targets.json` is signed by targets keys.
        *   `root.json` is signed by root keys. If initializing or rotating, `root_certificate` can be provided.
        *   `snapshot.json` is signed by snapshot keys.
        *   (Note: `timestamp.json` is typically signed by an online server key, but client might prepare data for it).
    *   It updates version numbers and expiration dates for the metadata.
    *   Finally, it uses `JsonStore.publish()` to upload the signed metadata files.

### `class Metafile` (and its subclasses: `Root`, `Snapshot`, `Targets`, `Timestamp`)

This is a base class for representing and manipulating TUF metadata files. Each subclass corresponds to one of an important TUF role's metadata.

-   **Common Attributes:**
    *   `bytes`: Raw byte content of the metadata file.
    *   `data`: Parsed JSON content of the metadata file (usually `{"signed": {...}, "signatures": [...]}`).
    *   `dirty`: Boolean flag indicating if the metadata has been modified and needs re-signing/publishing.
    *   `name`: Static attribute defining the role name (e.g., "root", "snapshot").
    *   `EXPIRATION_DELAY`: Default expiration time for this type of metadata.

-   **Common Methods:**
    *   `version()`: Returns the version number from the `signed` part.
    *   `expires()`: Returns the expiration date from the `signed` part.
    *   `hash()`: Calculates the SHA256 hash of the raw `bytes`.
    *   `hashes()`: Generates a TUF-compliant hash dictionary (sha256, sha512, length).
    *   `check_hashes(self, hashes)`: Verifies if the current metadata's hashes match a provided hash dictionary.
    *   `verify_sign(self, root_metafile)`: Verifies the signatures on the current metadata file using public keys obtained from a trusted `Root` metafile object.
    *   `to_bytes(self, private_keys)`: Updates the version and expiration, then signs the `signed` part of the data with the provided `private_keys` and rebuilds the `bytes` with the new signatures.

-   **Subclass Specifics:**
    *   **`Root`**:
        *   Manages public keys for all roles (`data['signed']['keys']`) and role definitions (`data['signed']['roles']` including thresholds).
        *   `get_keys(self, role)`: Retrieves public keys for a specified role.
        *   `verify_trust_pinning()`: Implements trust pinning checks.
        *   `add_key()`, `add_root_key()`, `add_root_certificate()`: Methods for adding new keys/certificates to the root metadata.
    *   **`Targets`**:
        *   Manages target information (`data['signed']['targets']` which maps target names to their hash metadata) and delegations (`data['signed']['delegations']`).
        *   `__getitem__(self, target)`: Accesses metadata for a specific target.
        *   `add_target_hashes()`: Adds/updates target hash information.
    *   **`Snapshot`**:
        *   Contains version information for other metadata files (`data['signed']['meta']`, e.g., `snapshot['targets']` gives the version of `targets.json`).
        *   `update(self, metafile_object)`: Updates the version entry for the given metafile object.
    *   **`Timestamp`**:
        *   Contains version information for `snapshot.json`.

### `class JsonStore`

Handles the actual HTTP communication with the Notary server's TUF repository.

-   **`__init__(self, path, url, config, verify=None)`:**
    *   `path`: Local cache path for this repository's TUF files.
    *   `url`: Base URL of the Notary server for this repository.
    *   `config`: `ConcilConfig`-like object for trust pinning, etc.
-   **`get(self, metafileclass, hashes=None, name=None)`:**
    *   Fetches a specific TUF metadata file (e.g., `root.json`, `targets.json`).
    *   Tries local cache first (`self.path / "<type>.json"`).
    *   If not cached, or if `hashes` are provided and don't match, downloads from the Notary server (e.g., `<server_url>/_trust/tuf/<type>.<version_or_hash>.json` or `<server_url>/_trust/tuf/<type>.json`).
    *   Performs version checks, expiration checks, and hash checks.
    *   For `root.json`, it handles root key rotation verification (checking new root against old root, and against trust pinning configuration).
    *   Caches the downloaded file.
-   **`publish(self, datas)`:**
    *   Uploads a list of `Metafile` objects (their raw `bytes`) to the Notary server.

### `class PrivateKeyStore`

Manages encrypted private keys stored on the local filesystem, typically in `~/.notary/private`.

-   **`__init__(self, path)`:** Sets the directory where keys are stored.
-   **`get_root()`:** Finds and loads the root key. If none exists, it can generate one.
-   **`generate_key(self, key_type, repository)`:** Generates a new ECDSA P-256 private key, prompts for a passphrase, encrypts it (PKCS#8 with AES), and saves it to a file named by its key ID.
-   **`get(self, key_id, key_type)`:** Loads an encrypted private key by its ID, prompts for the passphrase to decrypt it.

## Cryptographic Operations

-   **Signatures:** Primarily uses ECDSA with P-256 curve and SHA256 hashing for signing TUF metadata. Support for RSAPSS and EdDSA is partially indicated by `SIGNATURE_METHODS` but ECDSA is the main one for `encode_signed_json`.
-   **Hashing:** Uses SHA256 and SHA512 for file integrity checks within TUF metadata. `generate_hashes` and `check_hashes` are utility functions.
-   **Key Representation:** Public keys are stored in `root.json` in a TUF-specific format. Private keys are stored locally, encrypted.
-   **Certificates:** For the root role, X.509 certificates can be used to wrap public keys (`ecdsa-x509` keytype). The module includes functions to generate (`generate_certificate`) and verify (`verify_cert`) these certificates. This is often used for establishing the initial root of trust or for human-readable identification of root keys.
-   **JSON Canonicalization:** Metadata is signed over its canonical JSON representation (`encode_json` sorts keys and removes unnecessary whitespace).

## Workflow Examples

### Fetching and Verifying an Image Tag (Conceptual)

1.  `Notary(gun).get_digest_for_tag("latest")` is called.
2.  **Initialization:** `Notary.__init__` is triggered.
    *   `JsonStore.get(Timestamp)`: Fetches `timestamp.json`. Verifies its signature using known timestamp keys (or initial trust).
    *   `JsonStore.get(Snapshot, hashes=timestamp['snapshot'])`: Fetches `snapshot.json` matching the version in timestamp. Verifies against snapshot keys from a trusted root.
    *   `JsonStore.get(Root, hashes=snapshot['root'])`: Fetches `root.json`. Verifies against root keys (handling rotation if necessary and trust pinning). This becomes the trusted root.
    *   `JsonStore.get(Targets, hashes=snapshot['targets'])`: Fetches `targets.json`. Verifies against targets keys from the trusted root.
    *   If delegations exist and are relevant, they are fetched and verified recursively.
3.  The `Notary` instance now has verified `self.targets` (and potentially `self.delegate_targets`).
4.  `get_digest_for_tag` looks up "latest" in `self.targets.data['signed']['targets']` and returns its hash information.

### Publishing a New Tag (Conceptual)

1.  An image is pushed, and `concil` needs to update Notary.
2.  `notary_client = Notary(gun)` initializes and loads current metadata.
3.  `notary_client.add_target_hashes("newtag", {"sha256": "...", "length": ...})`. This marks `notary_client.targets` as dirty.
4.  `notary_client.publish()` is called:
    *   `PrivateKeyStore` retrieves the targets private key(s) (prompts for password).
    *   `Targets.to_bytes()` re-signs `targets.json`.
    *   `Snapshot.update(notary_client.targets)` updates the version of targets in `snapshot.json`.
    *   `PrivateKeyStore` retrieves snapshot key(s).
    *   `Snapshot.to_bytes()` re-signs `snapshot.json`.
    *   (Timestamp is usually updated by the server, but the client provides snapshot hash).
    *   `JsonStore.publish()` uploads the new `targets.json` and `snapshot.json` (and potentially `root.json` if keys were added/rotated).

This module is critical for ensuring that `concil` can securely consume images by verifying their source and integrity against a trusted Notary server.
