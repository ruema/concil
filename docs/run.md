# Container Execution Module (`concil.run`)

The `concil.run` module is the heart of Concil's container runtime. It is responsible for the low-level operations required to create isolated environments and execute containerized processes. This module makes extensive use of Linux-specific syscalls via `ctypes` to manage namespaces, filesystems, and processes.

## Core Functionalities

-   **Namespace Management:** Creates and configures new user, mount, and PID namespaces to isolate the container from the host and other containers.
-   **Filesystem Mounting:** Mounts the container's root filesystem (typically from squashfs layers), overlay filesystems for writability, pseudo-filesystems (`/proc`, `/dev`), and user-defined volumes.
-   **User/Group ID Mapping:** Maps host user and group IDs to different IDs within the container's user namespace, often mapping to `root` (0:0) inside the container.
-   **Process Execution:** Pivots the root filesystem to the container's view and executes the specified command or entrypoint within this isolated environment.
-   **Configuration Handling:** Parses image configurations to determine runtime parameters like environment variables, user IDs, working directory, and command arguments.
-   **Encrypted Layer Support:** Handles the necessary calls to obtain decryption keys for encrypted image layers when mounting.

## Key Constants and `ctypes` Interfacing

The module defines numerous constants for Linux syscalls and flags, such as:

-   `CLONE_NEWNS`, `CLONE_NEWUSER`, `CLONE_NEWPID`: Flags for the `clone` syscall.
-   `MS_RDONLY`, `MS_BIND`, `MS_REC`, `MS_PRIVATE`, `MS_SHARED`: Flags for the `mount` syscall.
-   `SYSCALL_PIDFD_OPEN`: Syscall number for `pidfd_open`.

It directly interfaces with `libc` for syscalls like `mount`, `chroot`, `umount`, `unshare`, `syscall`, `setresuid`, `setresgid`, `pivot_root`, `fchdir`.
It also includes a custom shared library `libsquash.so` (presumably `squashfuse`) for mounting squashfs layers, accessed via `libsquash.squash_main`.

## Namespace and User ID Management

-   **`clone(flags)`:** Uses `libc.syscall(CLONE, ...)` to create a new child process. The `flags` argument specifies which new namespaces the child should be created in (e.g., `CLONE_NEWUSER | CLONE_NEWNS`).
-   **`setgroups_control(cmd)`:** Writes to `/proc/self/setgroups` (e.g., to "deny" new groups before UID/GID mapping).
-   **`map_id(filename, id_from, id_to)`:** Writes to `/proc/self/uid_map` or `/proc/self/gid_map` to map a single host ID to a container ID.
-   **`map_userid(real_euid, real_egid, user_id=0, group_id=0)`:** Orchestrates the user ID mapping process. It first calls `setgroups_control("deny")`, then maps the effective host UID/GID (`real_euid`, `real_egid`) to the target `user_id` and `group_id` within the new user namespace. Finally, it calls `setresuid` and `setresgid` to switch to these new IDs within the namespace.

## Filesystem and Mount Management

-   **`get_mount_point()`:** Creates and returns a temporary directory path (e.g., in `$XDG_RUNTIME_DIR` or `/tmp`) to be used as a mount point.
-   **`mount_root(mount_point, layers)`:** Mounts the container's root filesystem.
    *   `layers`: A list of paths to squashfs layer files (potentially with decryption options appended to the filename string if layers are encrypted).
    *   It calls `libsquash.squash_main` (from `libsquash.so`) in a separate thread, which likely invokes `squashfuse` to mount the layers onto `mount_point`.
    *   `wait_for_device()` is used to pause execution until the mount operation is detected as complete (by checking `st_dev` of the mount point).
-   **`mount_overlay(mount_point, overlay_work_dir, mount_point_root)`:** Sets up an overlay filesystem.
    *   Uses an external `fuse-overlayfs` binary (located relative to the script).
    *   `lowerdir` is set to `mount_point_root` (the read-only base layers).
    *   `upperdir` and `workdir` are created within `overlay_work_dir`.
    *   The overlay is mounted onto `mount_point`.
    *   Returns the `subprocess.Popen` object for the `fuse-overlayfs` process.
-   **`mount_dir(mount_point, source, target, type, options)`:** A generic wrapper around `libc.mount` to mount a `source` to a `target` path within the main `mount_point`.
-   **`mount_volumes(mount_point, cwd, volumes)`:** Mounts user-specified volumes.
    *   `volumes`: A list of tuples `(source_path, mount_path, flags)`.
    *   `source_path` is resolved relative to `cwd`.
    *   Uses `mount_dir` with `MS_BIND | MS_REC` and potentially `MS_RDONLY`.
-   **`mount_std_volumes(mount_point)`:** Mounts standard necessary filesystems and files like `/proc`, `/dev`, `/tmp`, `/run`, `/etc/hosts`, `/etc/resolv.conf` into the container's mount namespace, typically using bind mounts from the host or creating new tmpfs mounts.
-   **`pivot_root(mount_point)`:** Implements the `pivot_root` mechanism to change the process's root filesystem to the fully assembled container `mount_point`. This is a complex operation involving `libc.pivot_root`, `os.chdir`, `libc.fchdir`, and remounting the new root as shared.
-   **`unmount(mount_path)`:** Calls `libc.umount2` with `MNT_DETACH` to unmount a filesystem.

## Configuration Classes

### `class AbstractConfig`

Base class for handling container configuration.

-   **`__init__(self, private_key=None, environment=None)`:** Initializes with optional private key path (for encrypted layers) and base environment.
-   **`parse_args(self, args)`:** Parses command-line arguments like `-e/--env`, `--env-file`, `-p/--private-key`, `-v/--volume`.
-   **`get_environment(self)`:** Constructs the container's environment dictionary based on the image configuration's `Env` array and the host environment.
-   **`get_userid(self, etc_path=None)`:** Parses the `User` field from the image config (e.g., "user", "uid", "user:group", "uid:gid") and returns `(uid, gid)` integers. Defaults to `0:0`.
-   **`working_dir` (property):** Returns the `WorkingDir` from the image config, or `/`.
-   **`build_commandline(self, args=None)`:** Constructs the final command to be executed, combining `Entrypoint` and `Cmd` from the image config with any additional `args`.
-   **`get_key(self, layer)`:** Retrieves the decryption key for an encrypted layer.
    *   It expects encryption information in `layer["annotations"]["org.opencontainers.image.enc.keys.jwe"]` (JWE token) and `layer["annotations"]["org.opencontainers.image.enc.pubopts"]`.
    *   The private key (`self.private_key`) is loaded from a PEM file (prompting for a password if encrypted and `CONCIL_ENCRYPTION_PASSWORD` is not set).
    *   It deserializes the JWE token to extract the symmetric key and nonce.
    *   Returns a string formatted for `libsquash.so` to use for decryption (e.g., `"AES_256_CTR,base64(symkey),base64(nonce)"`).
-   **`get_volumes(self)`:** Parses volume mount specifications provided via `args` and validates them against `Volumes` defined in the image config if `self.check_volumes` is true.

### `class LocalConfig(AbstractConfig)`

Subclass of `AbstractConfig` that loads the image manifest and configuration from local files (OCI image layout).

-   **`__init__(self, manifest_filename, ...)`:** Loads `manifest.json` and the config JSON file referenced within it.
-   **`get_layers(self)`:** Returns a list of layer file paths to be mounted.
    *   It resolves layer digests to actual filenames in the image layout.
    *   If a layer is encrypted (based on its media type), it calls `self.get_key(layer)` and appends the decryption information to the filename string, which `libsquash.so` presumably parses.
    *   Raises errors for unsupported media types (it primarily expects squashfs or encrypted squashfs).

## Container Execution Flow

1.  **`run(config, overlay_work_dir=None)` (Main entry point):**
    *   Performs architecture and OS checks from the image config.
    *   Gets current effective UID/GID.
    *   Creates temporary mount point(s) for the rootfs and optionally for overlayfs.
    *   Calls `clone(CLONE_NEWUSER | CLONE_NEWNS)` to create the first child process in new user and mount namespaces.
    *   **Inside this first child:**
        *   `map_userid()`: Maps host UID/GID to container UID/GID (e.g., 0:0).
        *   Calls `run_child(config, mount_point, mount_point2, overlay_work_dir)`.
        *   Exits with the status from `run_child`.
    *   The parent `run` process waits for this first child and then cleans up the main mount point(s).

2.  **`run_child(config, mount_point, mount_point2, overlay_work_dir)`:**
    *   `mount_root()`: Mounts the base image layers (squashfs) onto `mount_point`.
    *   If `overlay_work_dir` is provided:
        *   `mount_overlay()`: Mounts an overlay filesystem onto `mount_point2`, using `mount_point` as the lowerdir. The main `mount_point` for subsequent operations is then switched to `mount_point2`.
    *   `mount_volumes()`: Mounts user-defined volumes into the prepared rootfs.
    *   Calls `clone(CLONE_NEWPID | CLONE_NEWNS if overlay_work_dir else CLONE_NEWPID)` to create a second child process in a new PID namespace (and another mount namespace if overlay is used, ensuring PID 1 for the container's init process and further mount isolation).
    *   **Inside this second (grand)child:**
        *   `mount_std_volumes()`: Mounts `/proc`, `/dev`, etc.
        *   `commandline = config.build_commandline()`
        *   `environment = config.get_environment()`
        *   `pivot_root(mount_point)`: Changes the root filesystem to the container's view.
        *   `os.chdir(config.working_dir)`
        *   `os.execvpe(commandline[0], commandline, environment)`: Executes the container process.
        *   If exec fails, it raises an error.
    *   The parent `run_child` process waits for this second child.
    *   If overlay was used, it unmounts the overlay mount point and waits for the `fuse-overlayfs` process to terminate.
    *   Returns the exit status of the container process.

## `join(pid, args)` Function

-   Allows joining the namespaces of an already running container process.
-   Uses `libc.syscall(SYSCALL_PIDFD_OPEN, pid, ...)` to get a file descriptor for the target process.
-   Uses `libc.setns(fd, CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID)` to move the current process into the target's namespaces.
-   Changes directory to `/` and executes a command (default `/bin/sh`) or provided `args`.

This module is highly platform-dependent (Linux-specific) and requires appropriate permissions (often root, or unprivileged user namespaces enabled) to perform its operations. Testing it typically involves integration tests due to its heavy reliance on system state and syscalls.
