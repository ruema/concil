#!/usr/bin/python3
import ctypes
import ctypes.util
import json
import logging
import os
import platform
import subprocess
import sys
import tempfile
import threading
import time

from .oci_spec import current_architecture

logger = logging.getLogger(__name__)

CLONE = 0x38
SYSCALL_PIDFD_OPEN = 434
SIGCHLD = 17
CLONE_NEWNS = 0x00020000
CLONE_NEWUSER = 0x10000000
CLONE_NEWPID = 0x20000000
MS_RDONLY = 1
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 1 << 18
MS_SHARED = 1 << 20

_PATH_PROC_UIDMAP = "/proc/self/uid_map"
_PATH_PROC_GIDMAP = "/proc/self/gid_map"
_PATH_PROC_SETGROUPS = "/proc/self/setgroups"

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
libc.mount.argtypes = (
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_ulong,
    ctypes.c_char_p,
)
libc.chroot.argtypes = (ctypes.c_char_p,)
libc.umount.argtypes = (ctypes.c_char_p,)
libc.umount2.argtypes = (ctypes.c_char_p, ctypes.c_ulong)
libc.unshare.argtypes = (ctypes.c_ulong,)
libc.syscall.argtypes = (
    ctypes.c_ulong,
    ctypes.c_ulong,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
)
libsquash = ctypes.CDLL(os.path.join(os.path.dirname(__file__), "libsquash.so"))
libsquash.squash_main.argtypes = (ctypes.c_ulong, ctypes.POINTER(ctypes.c_char_p))


def setgroups_control(cmd):
    """Writes a command to /proc/self/setgroups.

    Args:
        cmd (str): The command to write ('allow' or 'deny').
    """
    with open(_PATH_PROC_SETGROUPS, "w", encoding="ASCII") as fd:
        fd.write(cmd)


def map_id(filename, id_from, id_to):
    """Writes an ID mapping to a file.

    Args:
        filename (str): The path to the mapping file (e.g., /proc/self/uid_map).
        id_from (int): The starting ID in the new namespace.
        id_to (int): The starting ID in the parent namespace.
    """
    with open(filename, "w", encoding="ASCII") as fd:
        fd.write("{id_from} {id_to} 1".format(id_from=id_from, id_to=id_to))


def clone(flags):
    """Clones the current process with new namespaces.

    Args:
        flags (int): The clone flags.

    Returns:
        int: The process ID of the new child process.
    """
    pid = libc.syscall(CLONE, SIGCHLD | flags, None, None, None, None)
    if pid < 0:
        raise RuntimeError("clone failed %s" % ctypes.get_errno())
    # pid = os.fork()
    # if pid == 0:
    #    result = libc.unshare(flags)
    #    if result:
    #        raise RuntimeError("unshare failed %s" % result)
    return pid


def map_userid(real_euid, real_egid, user_id=0, group_id=0):
    """Maps the user and group IDs in a new user namespace.

    Args:
        real_euid (int): The effective user ID in the parent namespace.
        real_egid (int): The effective group ID in the parent namespace.
        user_id (int, optional): The user ID in the new namespace.
            Defaults to 0.
        group_id (int, optional): The group ID in the new namespace.
            Defaults to 0.
    """
    setgroups_control("deny")
    map_id(_PATH_PROC_UIDMAP, user_id, real_euid)
    map_id(_PATH_PROC_GIDMAP, group_id, real_egid)
    libc.setresuid(user_id, user_id, user_id)
    libc.setresgid(group_id, group_id, group_id)


def unmount(mount_path):
    """Unmounts a filesystem.

    Args:
        mount_path (str): The path to the mount point.
    """
    if libc.umount2(mount_path.encode(), 2):  # MNT_FORCE = 1 MNT_DETACH = 2
        logger.error("unmount failed: %s", ctypes.get_errno())


def get_mount_point():
    """Gets a temporary directory to use as a mount point.

    Returns:
        str: The path to the mount point.
    """
    try:
        runtime = os.environ.get("XDG_RUNTIME_DIR") or "/tmp"
        return tempfile.mkdtemp(prefix="concil.", dir=runtime)
    except OSError:
        # RUNTIME_DIR not specified
        # fall back to /tmp
        runtime = "/tmp"
        return tempfile.mkdtemp(prefix="concil.", dir=runtime)


def mount_dir(mount_point, source, target, type, options):
    """Mounts a directory.

    Args:
        mount_point (str): The root mount point.
        source (str): The source path.
        target (str): The target path relative to the mount point.
        type (str): The filesystem type.
        options (int): The mount options.
    """
    target_path = os.path.join(mount_point, target)
    if libc.mount(
        source.encode(),
        target_path.encode(),
        None if not type else type.encode(),
        options,
        None,
    ):
        # ignore error if source does not exist
        errno = ctypes.get_errno()
        if errno != 22:
            raise RuntimeError(
                "Mounting %s -> %s failed (%s)\n" % (source, target, errno)
            )


def wait_for_device(mount_point, device):
    """Waits for a device to be mounted.

    Args:
        mount_point (str): The path to the mount point.
        device: The device ID of the parent mount.
    """
    for _ in range(1000):
        if device != os.stat(mount_point).st_dev:
            return
        time.sleep(0.001)
    raise RuntimeError("mount failed")


def mount_root(mount_point, layers):
    """Mounts the root filesystem using squashfuse.

    Args:
        mount_point (str): The path to the mount point.
        layers (list of str): A list of paths to the layer files.
    """
    device = os.stat(mount_point).st_dev
    args = (
        [b"squashfuse", b"-f"]
        + [l.encode() for l in reversed(layers)]
        + [mount_point.encode()]
    )
    args = (ctypes.c_char_p * len(args))(*args)
    threading.Thread(
        target=libsquash.squash_main, args=(len(args), args), daemon=True
    ).start()
    wait_for_device(mount_point, device)


def mount_overlay(mount_point, overlay_work_dir, mount_point_root, volumes=None):
    """Mounts an overlay filesystem using fuse-overlayfs.

    Args:
        mount_point (str): The path to the mount point.
        overlay_work_dir (str): The path to the overlay work directory.
        mount_point_root (str): The path to the root of the lower layers.
        volumes (list, optional): A list of volumes to mount in the overlay.
            Defaults to None.

    Returns:
        tuple: A tuple containing the overlay process object and the temporary
            work directory object.
    """
    device = os.stat(mount_point).st_dev
    os.makedirs(overlay_work_dir, exist_ok=True)
    work = tempfile.TemporaryDirectory(
        suffix=None, prefix=".wh..wh.", dir=overlay_work_dir
    )
    if volumes:
        for _, mount_dir, _ in volumes:
            os.makedirs(os.path.join(work.name, "volumes", mount_dir), exist_ok=True)
        lowerdir = f"{mount_point_root}:{os.path.join(work.name, 'volumes')}"
    else:
        lowerdir = mount_point_root
    overlay_process = subprocess.Popen(
        [
            os.path.join(os.path.dirname(__file__), "fuse-overlayfs"),
            "-f",
            "-o",
            f"lowerdir={lowerdir},upperdir={overlay_work_dir},workdir={work.name}",
            mount_point,
        ],
        env={"FUSE_OVERLAYFS_DISABLE_OVL_WHITEOUT": "yes"},
    )
    wait_for_device(mount_point, device)
    return overlay_process, work


def mount_volumes(mount_point, cwd, volumes):
    """Mounts volumes into the container.

    Args:
        mount_point (str): The root mount point of the container.
        cwd (str): The current working directory.
        volumes (list): A list of volumes to mount.
    """
    for source_path, mount_path, flags in volumes:
        mount_dir(
            mount_point,
            os.path.abspath(os.path.join(cwd, source_path)),
            mount_path,
            None,
            flags | MS_BIND | MS_REC,
        )


STD_VOLUMES = [
    ("proc", "proc"),
    (None, "dev"),
    ("tmpfs", "dev/shm"),
    ("tmpfs", "tmp"),
    ("tmpfs", "run"),
    (None, "etc/hosts"),
    (None, "etc/resolv.conf"),
]


def mount_std_volumes(mount_point):
    """Mounts standard volumes like /proc, /dev, etc.

    Args:
        mount_point (str): The root mount point of the container.
    """
    for fs_type, path in STD_VOLUMES:
        try:
            if fs_type is None:
                mount_dir(mount_point, "/" + path, path, None, MS_BIND | MS_REC)
            else:
                mount_dir(mount_point, fs_type, path, fs_type, 0)
        except RuntimeError:
            # ignore mount errors
            pass


def read_environment_file(filename):
    """Reads a file with key=value-pairs.

    Args:
        filename (str): The path to the environment file.

    Returns:
        dict: A dictionary of environment variables.
    """
    result = {}
    with open(filename) as lines:
        for line in lines:
            key, sep, value = line.strip().partition("=")
            if sep:
                if value[:1] == '"' and value[-1:] == '"':
                    value = json.loads(value)
                elif value[:1] == "'" and value[-1:] == "'":
                    value = value[1:-1]
                result[key] = value
    return result


class AbstractConfig:
    """An abstract base class for container configuration."""

    def __init__(self, private_key=None, environment=None):
        """Initializes the configuration.

        Args:
            private_key (str, optional): The path to the private key for
                decryption. Defaults to None.
            environment (dict or str, optional): A dictionary of environment
                variables or a path to an environment file. Defaults to None.
        """
        self.manifest = None
        self.config = None
        self.image_config = None
        self.private_key = private_key
        if environment is None:
            self.environment = dict(os.environ)
        elif isinstance(environment, dict):
            self.environment = dict(environment)
        else:
            self.environment = read_environment_file(environment)

        self.check_volumes = True
        self.volumes = []
        self.args = []

    def parse_args(self, args):
        """Parses command-line arguments.

        Args:
            args (list of str): The arguments to parse.
        """
        while args:
            if args[0] in ("-e", "--env"):
                if len(args) <= 1:
                    break
                key, sep, value = args[1].partition("=")
                if sep:
                    self.environment[key] = value
                args = args[2:]
            elif args[0] == "--env-file":
                if len(args) <= 1:
                    break
                self.environment.update(read_environment_file(args[1]))
                args = args[2:]
            elif args[0] in ("-p", "--private-key"):
                if len(args) <= 1:
                    break
                if self.private_key is not None:
                    print("only one private-key argument allowed")
                    return
                self.private_key = args[1]
                # --help --mount --tmpfs
            elif args[0] in ("-v", "--volume"):
                if len(args) <= 1:
                    break
                self.volumes.append(args[1])
                args = args[2:]
            elif args[0] == "--":
                args = args[1:]
                break
            else:
                break
        self.args = args

    def get_environment(self):
        """Gets the environment variables for the container.

        The environment variables are given in the from VAR=value.
        If no value is provided, the value is taken from the
        local environment.

        Returns:
            dict: A dictionary of environment variables.
        """
        environment = {}
        for env in self.config.get("Env", []):
            key, sep, value = env.partition("=")
            if not sep or not value:
                value = self.environment.get(key, "")
            environment[key] = value
        return environment

    def get_userid(self, etc_path=None):
        """Gets the user and group ID for the container.

        Args:
            etc_path (str, optional): The path to the /etc directory.
                Not used. Defaults to None.

        Returns:
            tuple: A tuple of (user_id, group_id).
        """
        # user, uid, user:group, uid:gid, uid:group, user:gid
        user = self.config.get("User") or "0:0"
        user, _, group = user.partition(":")
        return int(user), int(group)

    @property
    def working_dir(self):
        """str: The working directory for the container."""
        return self.config.get("WorkingDir") or "/"

    def build_commandline(self, args=None):
        """Builds the command line for the container.

        Args:
            args (list of str, optional): Additional arguments to append to
                the command line. Defaults to None.

        Returns:
            list of str: The command line.
        """
        entrypoint = self.config.get("Entrypoint", [])
        commandline = self.config.get("Cmd") or []
        if entrypoint:
            commandline = entrypoint + commandline
        if args:
            commandline.extend(args)
        elif self.args:
            commandline.extend(self.args)
        return commandline

    def get_key(self, layer):
        """Gets the decryption key for a layer.

        Args:
            layer (dict): The layer descriptor.

        Returns:
            str: The decryption key.
        """
        if self.private_key is None:
            self.private_key = os.environ.get("CONCIL_ENCRYPTION_KEY")
            if self.private_key is None:
                raise RuntimeError("no private key given")
        import getpass

        from jwcrypto import jwe, jwk
        from jwcrypto.common import base64url_decode, base64url_encode

        if isinstance(self.private_key, str):
            with open(self.private_key, "rb") as file:
                data = file.read()
            try:
                self.private_key = jwk.JWK.from_pem(data)
            except TypeError:
                passwd = os.environ.get("CONCIL_ENCRYPTION_PASSWORD")
                if not passwd:
                    passwd = getpass.getpass("password for encryption key: ")
                self.private_key = jwk.JWK.from_pem(data, passwd.encode())
        enc = base64url_decode(
            layer["annotations"]["org.opencontainers.image.enc.keys.jwe"]
        )
        pub_data = json.loads(
            base64url_decode(
                layer["annotations"]["org.opencontainers.image.enc.pubopts"]
            )
        )
        if pub_data["cipher"] != "AES_256_CTR_HMAC_SHA256":
            raise ValueError("unsupported cipher")
        jwetoken = jwe.JWE()
        jwetoken.deserialize(enc, key=self.private_key)
        payload = json.loads(jwetoken.payload)
        return "AES_256_CTR,{},{}".format(
            payload["symkey"], payload["cipheroptions"]["nonce"]
        )

    def get_volumes(self):
        """Gets the volumes for the container.

        Returns:
            list: A list of volumes to mount.
        """
        defined_volumes = self.config.get("Volumes") or {}
        if not self.volumes:
            return []
        result = []
        for volume in self.volumes:
            source_path, _, other = volume.partition(":")
            mount_path, _, flags = other.partition(":")
            flags = MS_RDONLY if "ro" in flags.split(",") else 0
            mount_path = mount_path.strip("/")
            if self.check_volumes and "/" + mount_path not in defined_volumes:
                raise RuntimeError("mount volume not defined")
            result.append((source_path, mount_path, flags))
        return result


class LocalConfig(AbstractConfig):
    """A container configuration loaded from a local directory."""

    def __init__(self, manifest_filename, private_key=None, environment=None):
        """Initializes the local configuration.

        Args:
            manifest_filename (str): The path to the manifest file or directory.
            private_key (str, optional): The path to the private key.
                Defaults to None.
            environment (dict or str, optional): A dictionary of environment
                variables or a path to an environment file. Defaults to None.
        """
        super().__init__(private_key, environment)
        if os.path.isdir(manifest_filename):
            manifest_filename = os.path.join(manifest_filename, "manifest.json")
        self.basepath = os.path.dirname(manifest_filename)
        with open(manifest_filename, "r", encoding="utf8") as file:
            self.manifest = json.load(file)
        config_filename = os.path.join(
            self.basepath, self.manifest["config"]["digest"].split(":", 1)[1]
        )
        with open(config_filename, "r", encoding="utf8") as file:
            self.image_config = json.load(file)
        self.config = self.image_config.get("config", {})

    def get_layers(self):
        """Gets the layers for the container.

        Returns:
            list of str: A list of paths to the layer files.
        """
        layers = {}
        for layer in self.manifest["layers"]:
            digest = layer["digest"]
            filename = os.path.join(self.basepath, digest.split(":", 1)[1])
            if (
                layer["mediaType"]
                == "application/vnd.docker.image.rootfs.diff.squashfs+encrypted"
            ):
                filename += "," + self.get_key(layer)
            elif (
                layer["mediaType"]
                == "application/vnd.docker.image.rootfs.diff.squashfs"
            ):
                pass
            else:
                raise RuntimeError(f"unsupported media type {layer['mediaType']}")
            layers[digest] = filename
        return [layers[l] for l in self.image_config["rootfs"]["diff_ids"]]


def pivot_root(mount_point):
    """Changes the root filesystem of the current process.

    Args:
        mount_point (str): The path to the new root filesystem.

    Returns:
        int: 0 on success, or a negative error code on failure.
    """
    fd_oldroot = os.open("/", 0)
    os.chdir(mount_point)

    ret = libc.mount(None, b"/", None, MS_PRIVATE | MS_REC, None)
    if ret < 0:
        logger.error("remounting root")
        return ret
    # ret = libc.mount(b".", b".", None, MS_BIND, None)

    # pivot_root into our new root fs
    ret = libc.pivot_root(".", ".")
    if ret < 0:
        logger.error("calling pivot")
        return ret

    # At this point the old-root is mounted on top of our new-root. To
    # unmounted it we must not be chdir'd into it, so escape back to
    # old-root.
    ret = libc.fchdir(fd_oldroot)
    if ret < 0:
        logger.error("calling chdir")
        return ret

    unmount(".")
    os.chdir("/")
    # Finally, we turn the rootfs into a shared mount. Note, that this
    # doesn't reestablish mount propagation with the hosts mount
    # namespace. Instead we'll create a new peer group.
    #
    # We're doing this because most workloads do rely on the rootfs being
    # a shared mount. For example, systemd daemon like sytemd-udevd run in
    # their own mount namespace. Their mount namespace has been made a
    # dependent mount (MS_SLAVE) with the host rootfs as it's dominating
    # mount. This means new mounts on the host propagate into the
    # respective services.
    #
    # This is broken if we leave the container's rootfs a dependent mount.
    # In which case both the container's rootfs and the service's rootfs
    # will be dependent mounts with the host's rootfs as their dominating
    # mount. So if you were to mount over the rootfs from the host it
    # would not just propagate into the container's mount namespace it
    # would also propagate into the service. That's nonsense semantics for
    # nearly all relevant use-cases. Instead, establish the container's
    # rootfs as a separate peer group mirroring the behavior on the host.
    ret = libc.mount(b"", b".", b"", MS_SHARED | MS_REC, None)
    if ret < 0:
        logger.error("final shared mount")
        return ret
    return 0


def run_child(config, mount_point=None, mount_point2=None, overlay_work_dir=None):
    """The main function for the child process that runs the container.

    Args:
        config (AbstractConfig): The container configuration.
        mount_point (str, optional): The primary mount point. Defaults to None.
        mount_point2 (str, optional): The secondary mount point for overlayfs.
            Defaults to None.
        overlay_work_dir (str, optional): The overlay work directory.
            Defaults to None.

    Returns:
        int: The exit code of the containerized process.
    """
    cwd = os.getcwd()
    volumes = config.get_volumes()
    mount_root(mount_point, config.get_layers())
    if overlay_work_dir:
        overlay_process, temp_work = mount_overlay(
            mount_point2,
            os.path.abspath(os.path.join(cwd, overlay_work_dir)),
            mount_point,
            volumes,
        )
        mount_point, mount_point2 = mount_point2, mount_point
    mount_volumes(mount_point, cwd, volumes)
    pid = clone(CLONE_NEWPID | CLONE_NEWNS if overlay_work_dir else CLONE_NEWPID)
    if pid == 0:
        mount_std_volumes(mount_point)
        commandline = config.build_commandline()
        environment = config.get_environment()
        # if libc.chroot(mount_point.encode()):
        if pivot_root(mount_point.encode()):
            raise RuntimeError("chroot failed: %s" % ctypes.get_errno())
        os.chdir(config.working_dir)
        os.execvpe(commandline[0], commandline, environment)
        raise RuntimeError("exec failed: %s" % ctypes.get_errno())
    pid, status = os.waitpid(pid, 0)
    if overlay_work_dir:
        time.sleep(0.1)
        unmount(mount_point)
        overlay_process.wait()
        temp_work.cleanup()
    if status & 0xFF:
        raise RuntimeError("program ended with signal %x" % status)
    return status >> 8


def run(config, overlay_work_dir=None):
    """Runs a container.

    Args:
        config (AbstractConfig): The container configuration.
        overlay_work_dir (str, optional): The overlay work directory.
            Defaults to None.

    Returns:
        int: The exit code of the container.
    """
    if (
        "architecture" in config.image_config
        and config.image_config["architecture"] != current_architecture()
    ):
        raise RuntimeError("unsupported architecture")
    if (
        "os" in config.image_config
        and config.image_config["os"] != platform.system().lower()
    ):
        raise RuntimeError("unsupported os")
    real_euid = os.geteuid()
    real_egid = os.getegid()
    mount_point = get_mount_point()
    mount_point2 = get_mount_point() if overlay_work_dir else None
    pid = clone(CLONE_NEWUSER | CLONE_NEWNS)
    if pid == 0:
        map_userid(real_euid, real_egid, *config.get_userid())
        status = run_child(config, mount_point, mount_point2, overlay_work_dir)
        os._exit(status)
    pid, status = os.waitpid(pid, 0)
    os.rmdir(mount_point)
    if mount_point2:
        os.rmdir(mount_point2)
    if status & 0xFF:
        raise RuntimeError("program ended with signal %x" % status)
    return status >> 8


def join(pid, args):
    """Joins the namespaces of a running process.

    Args:
        pid (int): The process ID to join.
        args (list of str): The command to execute in the new namespaces.
    """
    fd = libc.syscall(SYSCALL_PIDFD_OPEN, pid, 0, None, None, None)
    if fd < 0:
        logger.error("pidfd_open failed: %s", ctypes.get_errno())
        return
    if libc.setns(fd, CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID) < 0:
        logger.error("setns failed: %s", ctypes.get_errno())
        return
    os.chdir("/")
    commandline = args or ["/bin/sh"]
    os.execvpe(commandline[0], commandline, {})


def main():
    """The main entry point for the run script."""
    if len(sys.argv) <= 1:
        print("Usage: run.py [config.json] [-p private_key.pem] [-v volume] args")
        return
    config_filename = sys.argv[1]
    config = LocalConfig(config_filename)
    config.parse_args(sys.argv[2:])
    sys.exit(run(config))


if __name__ == "__main__":
    main()
