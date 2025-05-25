# Concil Architecture

Concil is designed as a modular userspace OCI container runtime. Its architecture revolves around several key components that manage different aspects of the container lifecycle. This document provides an overview of these components and how they interact.

## Core Components

1.  **CLI (`concil/cli.py`, `concil_run.py`, `concil_join.py`):**
    *   Provides the command-line interface for users to interact with Concil.
    *   Parses user commands (`list`, `copy`, `shell`, `publish`, `config`) and orchestrates calls to other modules.
    *   `concil_run.py` is the primary entry point for running containers.
    *   `concil_join.py` allows joining the namespaces of an already running container.

2.  **Configuration (`concil.store.ConcilConfig`):**
    *   Manages global configuration for Concil, such as cache directories, content trust preferences (Notary/Cosign), remote server URLs (registry, Notary), and authentication details.
    *   Typically loaded from `~/.concil/config.json` or system-wide configuration if present.

3.  **Store (`concil.store.Store`):**
    *   Acts as a high-level facade for accessing and managing container images.
    *   Integrates with the `DockerHub` client for registry interactions.
    *   If content trust is enabled, it coordinates with `Notary` or `Cosign` modules for signature verification and publishing.
    *   Manages a local cache for image manifests, configurations, and layers to optimize performance and reduce network traffic.
    *   Handles on-the-fly image layer format conversions (e.g., from tarball to squashfs using the `tar2sqfs` tool).

4.  **Image Representation (`concil.image`):**
    *   `ImageManifest`: Represents an OCI image manifest (or Docker v2 manifest). Handles loading manifests from local paths or remote registries, parsing their structure, and providing access to image configuration and layers.
    *   `LayerDescriptor`: Represents an individual image layer. It manages the layer's media type, digest, size, annotations, and its actual data (which can be on disk or in memory). This class also handles layer export, conversion between formats (e.g., directory to tar, tar to squashfs), and OCI-compliant layer encryption/decryption.

5.  **OCI Specification (`concil.oci_spec`):**
    *   Defines OCI media type constants (e.g., for manifests, layers, configs).
    *   Provides helper classes like `Descriptor` to represent OCI content descriptors.
    *   Includes functions (`descriptor_to_dict`, `manifest_to_dict`) to convert internal representations to OCI-compliant dictionary structures suitable for JSON serialization.
    *   Ensures that Concil adheres to OCI standards when creating or interpreting image metadata.

6.  **Registry Interaction (`concil.dockerhub.DockerHub`):**
    *   Provides the low-level client functionality to interact with OCI-compliant container registries.
    *   Handles parsing of `docker://` URLs to extract necessary components (host, repository, tag, authentication).
    *   Manages authentication with registries, including token-based negotiation.
    *   Implements OCI registry API calls (GET/POST/PUT/HEAD for manifests and blobs/layers).

7.  **Content Trust:**
    *   **Notary (`concil.notary`):** Implements a client for Notary v1, which is based on The Update Framework (TUF). It manages cryptographic keys, fetches and verifies TUF metadata (root, snapshot, targets, timestamp files), and can publish signed metadata to a Notary server. This ensures the authenticity and integrity of images by verifying publisher signatures.
    *   **Cosign (`concil.cosign`):** Implements Cosign-style signing and verification. It generates a "simple signing" JSON blob containing image metadata, signs this blob using an ECDSA private key, and then publishes this signature as an OCI manifest attachment (often tagged as `sha256-<digest>.sig`) in the registry. It can also verify these signatures.

8.  **Container Execution (`concil.run`):**
    *   This is the core runtime engine responsible for actually running containers. It's a complex module that leverages low-level Linux kernel features:
        *   **Namespaces:** Creates new user, mount, and PID namespaces using `clone()` and `unshare()` syscalls (via `ctypes`) to provide isolation between the container and the host, and among containers.
        *   **Filesystem Management:**
            *   Mounts image layers. Concil primarily uses squashfs layers, which are mounted using a custom `libsquash.so` (interfacing with `squashfuse`).
            *   Optionally sets up an overlay filesystem using an external `fuse-overlayfs` binary to provide a writable layer on top of the read-only image layers.
            *   Mounts standard pseudo-filesystems like `/proc`, `/dev`, `/tmp`, `/run`, and files like `/etc/hosts`, `/etc/resolv.conf` into the container.
            *   Mounts user-specified volumes.
            *   Uses `pivot_root` to switch the container's root filesystem to the prepared mount point.
        *   **User/Group Mapping:** Within the new user namespace, it maps the host user/group IDs to the container's target user/group IDs (often root, 0:0, inside the container).
        *   Loads the image configuration (entrypoint, command, environment variables, working directory) using `LocalConfig`, which reads the OCI image spec.
        *   Handles decryption of encrypted image layers if necessary, using keys provided via environment variables or other secure means.
        *   Ultimately, it executes the container's command using `os.execvpe` within the fully prepared and isolated environment.

9.  **Streams (`concil.streams`):**
    *   Provides utility classes for advanced stream manipulation, crucial for image layer processing:
        *   `_Stream`: A base class for creating buffered stream objects.
        *   `GZipStream`: For gzipping content on the fly when producing gzipped tarballs.
        *   `DirTarStream`: For creating a tar archive directly from a directory's contents.
        *   `MergedTarStream`: For merging multiple tar streams into a single output stream. This is particularly important for implementing layer modifications, as it correctly handles TUF/OCI whiteouts (`.wh..wh..opq` files) to simulate file deletions or modifications in overlay filesystems.

## High-Level Operational Flows

### 1. Pulling/Preparing an Image (e.g., for `concil_run` or as a source for `concil copy`)

1.  The **CLI** parses the user's command (e.g., `concil_run docker://ubuntu:latest`).
2.  The **Store** component is instantiated with the image URL.
3.  The **Store** utilizes the **DockerHub** client to communicate with the registry specified in the URL.
4.  If content trust (Notary or Cosign) is enabled in the **Configuration**, the **Store** invokes the respective module (**Notary** or **Cosign**) to fetch and verify signatures for the image manifest.
5.  The **DockerHub** client downloads the image manifest. If it's a manifest list, the **Store** selects the appropriate manifest for the current architecture/OS.
6.  The **DockerHub** client then downloads the image configuration blob and all layer blobs referenced in the manifest.
7.  Downloaded items are stored in a local cache directory managed by the **Store**.
8.  If layers are downloaded in tar or tar+gzip format, the **Store** may convert them to squashfs format using its internal `tar2sqfs` invocation. This is because Concil's runtime primarily expects squashfs layers for efficient mounting.
9.  The prepared image, now typically in an OCI Image Layout on the local filesystem (with squashfs layers), is represented by **ImageManifest** and **LayerDescriptor** objects from the `concil.image` module.

### 2. Running a Container (`concil_run.py`)

1.  The image is first prepared (as described in the flow above), resulting in a local OCI image layout with read-only squashfs layers.
2.  `concil.run.LocalConfig` loads the image manifest and configuration from this local layout.
3.  The main `concil.run.run()` function orchestrates the container setup:
    *   It calls `clone()` to create a new process in new **user** and **mount namespaces**.
    *   Inside this new namespace, `map_userid` is called to map the effective host UID/GID to the target UID/GID within the container (often 0:0).
    *   `run_child` is invoked:
        *   The squashfs layers are mounted via `libsquash.so` (squashfuse) to create the container's root filesystem.
        *   If a writable environment is needed (e.g., for `concil shell` or if the image requires it), `fuse-overlayfs` is used to mount an overlay filesystem on top of the squashfs layers.
        *   User-specified volumes and standard pseudo-filesystems (`/proc`, `/dev`, etc.) are mounted.
        *   `clone()` is called again to create another new process in a new **PID namespace** (and potentially another mount namespace if overlayfs is used, for further isolation).
        *   Inside this innermost child process:
            *   `pivot_root` is called to make the prepared root filesystem the actual root (`/`) of the process.
            *   The process changes to the `WorkingDir` specified in the image configuration.
            *   Finally, `os.execvpe` executes the command defined by the image's `Entrypoint` and `Cmd`, using environment variables from the image config and host.
4.  The initial `concil_run.py` process waits for the container to exit and then cleans up mounts and temporary directories.

### 3. Copying/Modifying an Image (`concil copy`)

1.  The source image is loaded using `ImageManifest.from_path()`. This might involve fetching from a registry (Flow 1) if a `docker://` URL is provided, or loading from a local directory.
2.  The user's requested modifications (e.g., adding a new layer from a local directory, removing layers, changing environment variables in the config) are applied by:
    *   Creating new `LayerDescriptor` objects for added layers (e.g., using `DirTarStream` to tar a directory, then potentially converting to squashfs).
    *   Marking existing `LayerDescriptor` objects for removal or merging.
    *   Updating the image configuration dictionary held by the `ImageManifest` object.
3.  `ImageManifest.export()` is called to write the modified image to the destination path:
    *   For each layer in the modified manifest:
        *   `LayerDescriptor.export()` is invoked. This method handles:
            *   Simply copying existing blobs if they are unchanged.
            *   Using `DirTarStream` for new layers created from directories.
            *   Employing `MergedTarStream` if multiple layers are being squashed into one (this stream handles whiteout files correctly).
            *   Converting layers to the desired output format (e.g., squashfs via `tar2sqfs`).
            *   Encrypting layers if OCI encryption is requested.
        *   The `LayerDescriptor` for the newly processed layer (with its new digest and size) is collected.
    *   The image configuration's `rootfs.diff_ids` (the ordered list of layer digests) is updated to reflect the changes.
    *   The (potentially modified) configuration blob is exported.
    *   A new OCI manifest (`manifest.json`) is generated and written to the destination directory, along with an OCI layout `version` file.
