# Command Line Interface (CLI)

The `concil` command-line interface provides users with tools to manage and interact with OCI-conformant Linux containers. This document outlines the available commands and their functionalities.

## Main Commands

The CLI is invoked via the main script (e.g., `concil_cli.py` or an entry point script). It supports the following primary commands:

- `list`: Inspects an image and displays its layers and metadata.
- `copy`: Modifies an image by adding, removing, or converting layers, and updating its configuration.
- `shell`: Starts an interactive shell session within a container.
- `publish`: Publishes an image to a Docker registry, optionally signing it with Cosign and Notary.
- `config`: Manages `concil` configuration, currently focused on Cosign key management.

---

### `list`

Displays information about a specified container image.

**Usage:**

```shell
concil list <image_path> [--config] [--history]
```

**Arguments:**

- `<image_path>`: Path to the image directory.

**Options:**

- `--config`: Show the image's configuration details (entrypoint, command, environment variables, volumes, etc.).
- `--history`: Show the image's layer history.

**Output:**

- Lists layer digests, sizes, and media types.
- If `--config` is used, displays detailed configuration.
- If `--history` is used, displays layer creation history.

---

### `copy`

Creates a new image or modifies an existing one by performing operations on its layers and configuration.

**Usage:**

```shell
concil copy <source_image_path> <destination_image_path> [options...]
```

**Arguments:**

- `<source_image_path>`: Path to the source image directory.
- `<destination_image_path>`: Path where the new/modified image will be saved.

**Options:**

- `--squashfs`: Convert layers to squashfs format.
- `--tar`: Convert layers to tar+gzip format.
- `--encryption <key_file>`: Encrypt layers using the specified key(s). Can be used multiple times.
- `--remove-layer <layer_digest_prefix>`: Remove layer(s) matching the digest prefix. Can be used multiple times.
- `--add-layer <file_or_dir_path>`: Add a new layer from a file (squashfs, tar, tar.gz) or directory. Can be used multiple times.
- `--merge-layers <layer_digest_prefixes>`: Merge multiple layers into one. Provide a list of digest prefixes; the first layer in the list is the base, and others are merged into it.
- `--env <Key=Value>` or `--env <Key>`: Set or update environment variables. If only `<Key>` is provided, it's added to the environment. If `<Key>=` is provided, the variable is effectively removed if it exists. Can be used multiple times.
- `--volumes <volume_path>`: Define volumes for the container. Can be used multiple times.
- `--entrypoint "<command>"`: Set the entrypoint for the image.
- `--working-dir <path>`: Set the working directory for the image.

---

### `shell`

Launches an interactive shell (typically `/bin/sh`) inside the specified container image.

**Usage:**

```shell
concil shell <image_path> [--overlay-dir <path>] [-v <host_path:container_path>] [-- <args...>]
```

**Arguments:**

- `<image_path>`: Path to the image directory.

**Options:**

- `--overlay-dir <path>`: Specifies a directory to use for overlayfs, allowing for writable changes within the container session that don't modify the base image.
- `-v <host_path:container_path>` or `--volume <host_path:container_path>`: Mount a volume from the host into the container. Can be used multiple times.
- `<args...>`: Additional arguments to pass to the shell or command executed in the container.

---

### `publish`

Publishes the container image to a Docker registry.

**Usage:**

```shell
concil publish <image_path> <docker_url> [--root-certificate <path>] [--cosign-key <path>]
```

**Arguments:**

- `<image_path>`: Path to the image directory to be published.
- `<docker_url>`: The target Docker URL (e.g., `docker://docker.io/username/repository:tag`).

**Options:**

- `--root-certificate <path>`: Path to the root certificate for Notary (if used for signing).
- `--cosign-key <path>`: Path to the Cosign key for signing the image.

---

### `config`

Manages `concil` configurations. Currently, it primarily handles Cosign keys used for image signing.

**Sub-commands:**

#### `config cosign-list-keys`

Lists all available Cosign keys (both public and private) stored in the `concil` configuration.

**Usage:**

```shell
concil config cosign-list-keys
```

#### `config cosign-generate-key`

Generates a new Cosign key pair (public and private).

**Usage:**

```shell
concil config cosign-generate-key <key_id>
```

**Arguments:**

- `<key_id>`: A unique identifier for the new key pair. You will be prompted for a password to secure the private key.

#### `config cosign-export-key`

Exports a stored Cosign key (public or private) to a file.

**Usage:**

```shell
concil config cosign-export-key <key_id> <filename> [--private]
```

**Arguments:**

- `<key_id>`: The ID of the key to export.
- `<filename>`: The path where the key will be saved.

**Options:**

- `--private`: Export the private key. If not specified, the public key is exported.

#### `config cosign-import-key`

Imports a Cosign key (public or private) from a file into the `concil` configuration.

**Usage:**

```shell
concil config cosign-import-key <key_id> <filename>
```

**Arguments:**

- `<key_id>`: A unique identifier to assign to the imported key.
- `<filename>`: The path to the key file to import. You may be prompted for a password if importing an encrypted private key.

---

## Helper Functions

The `cli.py` module also contains internal helper functions for tasks like:

- **Key Generation and Loading:** `generate_key`, `load_encryption_keys` for handling encryption keys.
- **Environment Variable Parsing:** `split_env` for parsing `KEY=VALUE` strings.
- **Digest Resolution:** `find_digest`, `resolve_one_digest`, `resolve_digests` for finding and resolving full image layer digests from short prefixes or ranges. These are crucial for commands like `copy` when specifying layers to remove or merge.
- **Cosign Key Storage:** `store_concil_key` for saving Cosign keys to the configuration directory.

These functions support the main command handlers by processing arguments and interacting with other parts of the `concil` system.
