from pathlib import Path
import urllib.parse
from .dockerhub import DockerHub, parse_docker_url
from .notary import Notary, check_hashes
import base64
import json
import hashlib
import time
import logging
import subprocess
import gzip
import shutil
from jwcrypto.common import base64url_decode, base64url_encode
logger = logging.getLogger(__name__)

TAR2SQFS = "tar2sqfs"

def unsplit_url(scheme, hostname, port=None, path=None, username=None, password=None):
    auth = ""
    if username:
        if password:
            auth = f"{username}:{password}@"
        else:
            auth = f"{username}@"
    if port:
        url = f"{scheme}://{auth}{hostname}:{port}"
    else:
        url = f"{scheme}://{auth}{hostname}"
    if path:
        if path.startswith('/'):
            url += path
        else:
            url += f'/{path}'
    return url

def _convert_tar_to_squash(filename, stream):
    digest = hashlib.sha256()
    sq_filename = filename.with_suffix('.sq')
    process = subprocess.Popen([TAR2SQFS, "-fq", str(sq_filename)], stdin=subprocess.PIPE)
    while True:
        buf = stream.read(16*1024)
        if not buf:
            break
        digest.update(buf)
        process.stdin.write(buf)
    process.stdin.close()
    if process.wait():
        raise RuntimeError()
    sq_filename.rename(filename)
    return digest.hexdigest()

def convert_tar_gzip(filename):
    with gzip.open(filename, mode="rb") as stream:
        return _convert_tar_to_squash(filename, stream)

def convert_tar(filename):
    with filename.open("rb") as stram:
        return _convert_tar_to_squash(filename, stream)

IMAGE_CONVERTERS = {
    'application/vnd.docker.image.rootfs.diff.tar': convert_tar,
    'application/vnd.docker.image.rootfs.diff.tar.gzip': convert_tar_gzip,
}

class Store:
    CONFIG_PATH = "~/.concil/config.json"
    CONFIG_PARAMS = {
        "cache_dir" : "~/.concil",
        "cache_timeout": 604800,
        "disable_content_trust": False,
        "remote_servers": {
            "docker.io": {
                "registry": "https://registry.hub.docker.com",
                "notary": "https://notary.docker.io",
            },
        },
    }
    def __init__(self, url, config_path=CONFIG_PATH, verify=None):
        url = parse_docker_url(url)
        # 'docker://docker.io/library/alpine:latest'
        if url.scheme != "docker":
            raise ValueError("only docker://-url is supported")
        try:
            with Path(config_path).expanduser().open(encoding="utf8") as config_file:
                config = json.load(config_file)
        except FileNotFoundError:
            config = self.CONFIG_PARAMS
        if verify is None:
            verify = Path(config['cafile']).expanduser()
        disable_content_trust = config.get("disable_content_trust", False)
        registry_url = notary_url = None
        self._cache_dir = Path(config['cache_dir']).expanduser()
        self._cache_timeout = config.get('cache_timeout', 604800)
        if 'remote_servers' in config:
            if url.hostname in config['remote_servers']:
                info = config['remote_servers'][url.hostname]
                registry_url = info.get('registry')
                notary_url = info.get('notary')
        if registry_url is None:
            registry_url = unsplit_url("https", url.hostname, url.port)
        registry_url = parse_docker_url(registry_url)
        full_url = unsplit_url(registry_url.scheme, registry_url.hostname, registry_url.port, url.path, url.username, url.password)
        logger.debug("full registry url: %s", full_url)
        self._hub = DockerHub(full_url, verify=verify)
        if disable_content_trust:
            self.target = None
        else:
            if notary_url is None:
                notary_url = registry_url
                port = 4443
            else:
                notary_url = parse_docker_url(notary_url)
                port = notary_url.port
            path = f"{url.hostname}/{url.repository}"
            full_url = unsplit_url(notary_url.scheme, notary_url.hostname, port, path, url.username, url.password)
            logger.debug("full notary url: %s", full_url)
            notary = Notary(full_url, config={"trust_dir" : self._cache_dir / "notary"})
            targets = notary.targets.data['signed']['targets']
            self.target = targets[url.tag]
            logger.debug("notary target for %s: %r", url.tag, self.target)

    def cache_cleanup(self):
        cache_time = time.time() - self._cache_timeout
        for type in ['manifest', 'config', 'layers']:
            for filename in (self._cache_dir / type).iterdir():
                if filename.start().st_mtime < cache_time:
                    filename.unlink()

    def store_cache(self, type, bytes, digest=None):
        if digest is None:
            digest = hashlib.sha256(bytes).hexdigest()
        path = self._cache_dir / type
        path.mkdir(parents=True, exist_ok=True)
        logging.debug("storing %s/%s (%s bytes)", path, digest, len(bytes))
        (path / digest).write_bytes(bytes)

    def get_cache(self, type, digest):
        filename = self._cache_dir / type / digest
        logging.debug("trying cache %s", filename)
        bytes = filename.read_bytes()
        filename.touch()
        logging.debug("%s bytes read", len(bytes))
        return bytes

    def get_manifest(self, architecture=None, operating_system=None):
        if not self.target:
            manifest = self._hub.get_manifest(accept='application/vnd.docker.distribution.manifest.v2+json')
        else:
            hex_hash = base64.b16encode(base64url_decode(self.target['hashes']['sha256'])).decode('ascii').lower()
            hex_digest = f"sha256:{hex_hash}"
            try:
                manifest = self.get_cache("manifest", hex_digest)
            except FileNotFoundError:
                manifest = self._hub.get_manifest(hash=hex_digest, accept=None)
                if not check_hashes(manifest, self.target):
                    raise ValueError("hash check failed")
                self.store_cache("manifest", manifest, hex_digest)
        manifest = json.loads(manifest)
        if manifest['mediaType'] == 'application/vnd.docker.distribution.manifest.list.v2+json':
            for entry in manifest['manifests']:
                platform = entry['platform']
                if platform['architecture'] == architecture and platform['os'] == operating_system:
                    break
            else:
                raise ValueError("no matching platform found")
            filename = self._get_blob("manifest", entry)
            with filename.open("rb") as input:
                manifest = json.load(input)
        return manifest

    def _get_blob(self, type, entry):
        filename = self._cache_dir / type / entry['digest']
        logging.debug("trying cache %s", filename)
        if filename.is_file():
            filename.touch()
            filename = filename.resolve()
            filename.touch()
            return filename
        filename.parent.mkdir(parents=True, exist_ok=True)
        output_filename = filename.with_suffix('.out')
        try:
            with output_filename.open('xb') as output:
                if type == "manifest":
                    response = self._hub.open_manifest(hash=entry['digest'], accept=None)
                else:
                    response = self._hub.open_blob(entry['digest'])
                digest = hashlib.sha256()
                size = 0
                with response:
                    for chunk in response.iter_content(102400):
                        if not chunk:
                            break
                        output.write(chunk)
                        size += len(chunk)
                        digest.update(chunk)
            if 'size' in entry and entry['size'] != size:
                raise ValueError("hash check failed")
            digest = digest.hexdigest()
            if f"sha256:{digest}" != entry['digest']:
                raise ValueError("hash check failed")
            convert = IMAGE_CONVERTERS.get(entry['mediaType'])
            if convert is not None:
                diff_digest = convert(output_filename)
                diff_filename = self._cache_dir / type / f"sha256:{diff_digest}"
            else:
                diff_filename = filename
            output_filename.rename(diff_filename)
            if diff_filename != filename:
                try:
                    filename.symlink_to(diff_filename.name)
                except FileExistsError:
                    pass
        except FileExistsError:
            # some other process is downloading the same file
            while output_filename.is_file():
                time.sleep(1)
            if not filename.is_file():
                # something went wrong
                raise ValueError("downloading failed")
        finally:
            try:
                output_filename.unlink() # TODO: Python3.8 missing_ok=True
            except FileNotFoundError:
                pass
        return filename.resolve()

    def get_config(self, entry):
        filename = self._get_blob("config", entry)
        with filename.open('rb') as input:
            return json.load(input)

    def get_layer(self, entry):
        return self._get_blob("layers", entry)
