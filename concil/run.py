#!/usr/bin/python3
import sys
import os
import time
import json
import uuid
import subprocess
import argparse
import ctypes
import ctypes.util
import socket
import platform
import threading
import logging
from tempfile import mkdtemp
logger = logging.getLogger(__name__)

PLATFORMS = {
    'x86_64': 'amd64',
}

CLONE = 0x38
SIGCHLD = 17
CLONE_NEWNS = 0x00020000
CLONE_NEWUSER = 0x10000000
CLONE_NEWPID = 0x20000000
MS_RDONLY = 1
MS_BIND = 4096
MS_REC = 16384

_PATH_PROC_UIDMAP = "/proc/self/uid_map"
_PATH_PROC_GIDMAP = "/proc/self/gid_map"
_PATH_PROC_SETGROUPS = "/proc/self/setgroups"

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
libc.mount.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p)
libc.chroot.argtypes = (ctypes.c_char_p,)
libc.umount.argtypes = (ctypes.c_char_p,)
libc.umount2.argtypes = (ctypes.c_char_p, ctypes.c_ulong)
libc.unshare.argtypes = (ctypes.c_ulong, )
libc.syscall.argtypes = (ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
libsquash = ctypes.CDLL(os.path.join(os.path.dirname(__file__), 'libsquash.so'))
libsquash.squash_main.argtypes = (ctypes.c_ulong, ctypes.POINTER(ctypes.c_char_p))

def setgroups_control(cmd):
    with open(_PATH_PROC_SETGROUPS, 'w', encoding="ASCII") as fd:
        fd.write(cmd)

def map_id(filename, id_from, id_to):
    with open(filename, "w", encoding='ASCII') as fd:
        fd.write("{id_from} {id_to} 1".format(id_from=id_from, id_to=id_to))

def clone(re=False):
    """clone this process with new namespaces"""
    real_euid = os.geteuid()
    real_egid = os.getegid()
    #pid = os.fork()
    flags = CLONE_NEWPID if re else CLONE_NEWUSER|CLONE_NEWNS
    pid = libc.syscall(CLONE, SIGCHLD | flags, None, None, None, None)
    if pid < 0:
        raise RuntimeError("clone failed %s" % ctypes.get_errno())
    if pid == 0:
        #result = libc.unshare(CLONE_NEWUSER|CLONE_NEWNS|CLONE_NEWPID)
        #if result:
        #    raise RuntimeError("unshare failed %s" % result)
        if re:
            pass
            #map_id(_PATH_PROC_UIDMAP, 1, 0)
            #map_id(_PATH_PROC_GIDMAP, 1, 0)
        else:
            setgroups_control("deny")
            map_id(_PATH_PROC_UIDMAP, 0, real_euid)
            map_id(_PATH_PROC_GIDMAP, 0, real_egid)
        #pid2 = os.fork()
        #if pid2 != 0:
        #    os.waitpid(pid2, 0)
        #    sys.exit(0)
    return pid

def unmount(mount_path):
    """ unmount the mount path"""
    if libc.umount2(mount_path.encode(), 2):  # MNT_FORCE = 1 MNT_DETACH = 2
        logger.error("unmount failed: %s", ctypes.get_errno())

def get_mount_point():
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if not runtime:
        # RUNTIME_DIR not specified
        # fall back to /tmp
        runtime = "/tmp"
    return mkdtemp(prefix='concil.', dir=runtime)

def mount_dir(mount_point, source, target, type, options):
    target_path = os.path.join(mount_point, target)
    if libc.mount(source.encode(), target_path.encode(), None if not type else type.encode(), options, None):
        raise RuntimeError("Mounting %s failed\n" % target)

def sq_mount(layers, mount_path):
    """mount a squash image"""
    args = [b'squashfuse', b'-f'] + [l.encode() for l in reversed(layers)] + [mount_path.encode()]
    args = (ctypes.c_char_p * len(args))(*args)
    threading.Thread(target=libsquash.squash_main, args=(len(args), args), daemon=True).start()
    while not os.path.exists(os.path.join(mount_path, 'bin')):
        time.sleep(0.01)

def mount_volumes(mount_point, layers, volumes):
    sq_mount(layers, mount_point)
    for source_path, mount_path, flags in volumes:
        mount_dir(mount_point, source_path, mount_path, None, flags | MS_BIND | MS_REC)

def mount_std_volumes(mount_point):
    mount_dir(mount_point, "proc", "proc", "proc", 0)
    mount_dir(mount_point, "/dev", "dev", None, MS_BIND | MS_REC)
    mount_dir(mount_point, "tmpfs", "tmp", "tmpfs", 0)
    mount_dir(mount_point, "tmpfs", "run", "tmpfs", 0)
    mount_dir(mount_point, "/etc/resolv.conf", "etc/resolv.conf", None, MS_BIND | MS_REC)

class Config:
    def __init__(self, manifest_filename, private_key=None):
        self.basepath = os.path.dirname(manifest_filename)
        self.private_key = private_key
        with open(manifest_filename, 'r', encoding='utf8') as file:
            self.manifest = json.load(file)
        config_filename = os.path.join(self.basepath, self.manifest['config']['digest'].split(':',1)[1])
        with open(config_filename, 'r', encoding='utf8') as file:
            self.image_config = json.load(file)
        self.config = self.image_config.get('config', {})

    def get_environment(self):
        # remove all LD_-Variables like LD_LIBRARY_PATH or LD_PRELOAD
        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith('LD_') and not key.startswith('CONCIL_')
        }
        environment.update(e.split('=', 1) for e in self.config.get('Env', []))
        return environment

    @property
    def working_dir(self):
        return self.config.get('WorkingDir') or "/"

    def build_commandline(self, args=None):
        entrypoint = self.config.get('Entrypoint', [])
        commandline = self.config.get('Cmd') or []
        if entrypoint:
            commandline = entrypoint + commandline
        if args:
            commandline.extend(args)
        return commandline

    def get_key(self, layer):
        if self.private_key is None:
            self.private_key = os.environ.get('CONCIL_ENCRYPTION_KEY')
            if self.private_key is None:
                raise RuntimeError("no private key given")
        import getpass
        from jwcrypto import jwk, jwe
        from jwcrypto.common import base64url_decode, base64url_encode
        if isinstance(self.private_key, str):
            with open(self.private_key, 'rb') as file:
                data = file.read()
            try:
                self.private_key = jwk.JWK.from_pem(data)
            except TypeError:
                passwd = os.environ.get('CONCIL_ENCRYPTION_PASSWORD')
                if not passwd:
                    passwd = getpass.getpass("password for encryption key: ")
                self.private_key = jwk.JWK.from_pem(data, passwd.encode())
        enc = base64url_decode(layer["annotations"]["org.opencontainers.image.enc.keys.jwe"])
        pub_data = json.loads(base64url_decode(layer["annotations"]["org.opencontainers.image.enc.pubopts"]))
        if pub_data["cipher"] != "AES_256_CTR_HMAC_SHA256":
            raise ValueError("unsupported cipher")
        jwetoken = jwe.JWE()
        jwetoken.deserialize(enc, key=self.private_key)
        payload = json.loads(jwetoken.payload)
        return "AES_256_CTR,{},{}".format(payload['symkey'], payload["cipheroptions"]['nonce'])

    def get_layers(self):
        layers = {}
        for layer in self.manifest["layers"]:
            digest = layer["digest"]
            filename = os.path.join(self.basepath, digest.split(':', 1)[1])
            if layer["mediaType"] == "application/vnd.docker.image.rootfs.diff.squashfs+encrypted":
                filename += ',' + self.get_key(layer)
            elif layer["mediaType"] == "application/vnd.docker.image.rootfs.diff.squashfs":
                pass
            else:
                raise RuntimeError(f"unsupported media type {layer['mediaType']}")
            layers[digest] = filename
        return [layers[l]
            for l in self.image_config['rootfs']['diff_ids']
        ]

    def parse_volumes(self, volumes):
        defined_volumes = self.config.get('Volumes') or {}
        if not volumes:
            return []
        result = []
        for volume in volumes:
            source_path, _, other = volume.partition(':')
            mount_path, _, flags = other.partition(':')
            flags = MS_RDONLY if 'ro' in flags.split(',') else 0
            mount_path = mount_path.strip('/')
            if '/' + mount_path not in defined_volumes:
                raise RuntimeError("mount volume not defined")
            source_path = os.path.abspath(source_path)
            result.append((source_path, mount_path, flags))
        return result
    

def run_child(config, args=None, volumes=None):
    mount_point = get_mount_point()
    mount_volumes(mount_point, config.get_layers(), config.parse_volumes(volumes))
    pid = clone(True)
    if pid == 0:
        mount_std_volumes(mount_point)
        commandline = config.build_commandline(args)
        environment = config.get_environment()
        if libc.chroot(mount_point.encode()):
            raise RuntimeError("chroot failed: %s" % ctypes.get_errno())
        os.chdir(config.working_dir)
        # os.execve("/bin/sh", ["/bin/sh"], environment)
        os.execve(commandline[0], commandline, environment)
    else:
        os.waitpid(pid, 0)
    print("finished\n")
    unmount(mount_point)
    os.rmdir(mount_point)

def run(config, args=None, volumes=None):
    if "architecture" in config.image_config and config.image_config["architecture"] != PLATFORMS[platform.machine()]:
        raise RuntimeError("unsupported architecture")
    if "os" in config.image_config and config.image_config["os"] != platform.system().lower():
        raise RuntimeError("unsupported os")
    pid = clone()
    if pid == 0:
        run_child(config, args, volumes)
        os._exit(0)
    else:
        os.waitpid(pid, 0)
    
def main():
    if len(sys.argv) <= 1:
        print("Usage: run.py [config.json] [-p private_key.pem] [-v volume] args")
        return
    config_filename = sys.argv[1]
    volumes = []
    args = sys.argv[2:]
    if args and args[0] == '-p':
        private_key = args[1]
        args = args[2:]
    else:
        private_key = None
    while args and args[0] == '-v':
        volumes.append(args[1])
        args = args[2:]
    if args and args[0] == '--':
        args = args[1:]
    config = Config(config_filename, private_key)
    run(config, args, volumes)

if __name__ == '__main__':
    main()
