import os
import base64
import json
import hashlib
import time
import logging
import subprocess
import shutil
import urllib.parse
from pathlib import Path
from gzip import GzipFile
from .dockerhub import DockerHub, parse_docker_url
from .notary import Notary, check_hashes
logger = logging.getLogger(__name__)

TAR2SQFS = [os.path.join(os.path.dirname(__file__), "tar2sqfs"), "-c", "zstd", "-X", "level=10"]

def unsplit_url(scheme, netloc, path=None, username=None, password=None, port=None):
    auth = ""
    if "@" not in netloc and username:
        if password:
            auth = f"{username}:{password}@"
        else:
            auth = f"{username}@"
    url = f"{scheme}://{auth}{netloc}"
    if port:
        url += f":{port}"
    if path:
        if path.startswith('/'):
            url += path
        else:
            url += f'/{path}'
    return url

def complete_url_with_auth(url, config):
    repository = f"{url.hostname}{url.path}"
    auths = dict(config.params.get("auths", {}))

    # complete auths from environment
    for key in os.environ:
        if key.startswith('CONCIL_') and key.endswith('_REPO'):
            repo = os.environ[key]
            auth = os.environ.get(key.rsplit('_', 1)[0] + '_AUTH')
            if auth:
                auths[repo] = auth

    if repository in auths:
        auth = auths[repository]
    else:
        auth = None
        longest = 0
        for repo, repo_auth in auths.items():
            if repo.endswith('*') and len(repo) > longest and repository.startswith(repo[:-1]):
                longest = len(repo)
                auth = repo_auth
    if auth is None and url.hostname in auths:
        auth = auths[url.hostname]
    if auth is not None:
        auth = urllib.parse.quote_plus(base64.standard_b64decode(auth).decode(), safe=':')
        url = url._replace(netloc=f'{auth}@{url.netloc}')
    return url

def copyfileobj(fsrc, fdst, length=16*1024):
    """copy data from file-like object fsrc to file-like object fdst"""
    while True:
        buf = fsrc.read(length)
        if not buf:
            break
        fdst.write(buf)

def _convert_tar_to_squash(stream, output_filename):
    digest = hashlib.sha256()
    process = subprocess.Popen(TAR2SQFS + ["-fq", str(output_filename)], stdin=subprocess.PIPE)
    while True:
        buf = stream.read(16*1024)
        if not buf:
            break
        digest.update(buf)
        process.stdin.write(buf)
    process.stdin.close()
    if process.wait():
        raise RuntimeError()
    return digest.hexdigest()

def convert_tar_gzip(stream, output_filename):
    stream = GzipFile(fileobj=stream, mode="rb")
    return _convert_tar_to_squash(stream, output_filename)

def convert_tar(stream, output_filename):
    return _convert_tar_to_squash(stream, output_filename)

IMAGE_CONVERTERS = {
    'application/vnd.docker.image.rootfs.diff.tar': convert_tar,
    'application/vnd.docker.image.rootfs.diff.tar.gzip': convert_tar_gzip,
    "application/vnd.oci.image.layer.v1.tar": convert_tar,
    "application/vnd.oci.image.layer.v1.tar+gzip": convert_tar_gzip,
    "tar": convert_tar,
    "tar+gzip": convert_tar_gzip,
}


CONFIG_PATH = "~/.concil/config.json"
CONFIG_PARAMS = {
    "cache_dir" : "~/.concil",
    "cache_timeout": 604800,
    "disable_content_trust": False,
    "content_trust": "notary", #"cosign",#
    "remote_servers": {
        "docker.io": {
            "registry": "https://registry.hub.docker.com",
            "notary": "https://notary.docker.io",
        },
    },
}

class ConcilConfig:
    def __init__(self, config_path=None):
        if config_path is None:
            config_path = os.environ.get("CONCIL_CONFIG", CONFIG_PATH)
        config_path = Path(config_path).expanduser()
        try:
            with config_path.open(encoding="utf8") as config_file:
                params = json.load(config_file)
        except FileNotFoundError:
            params = CONFIG_PARAMS
        self.path = config_path
        self.params = params

    @property
    def cafile(self):
        """ returns the cafile as Path if set """
        if 'cafile' in self.params:
            return Path(self.params['cafile']).expanduser()
        return None

    @property
    def disable_content_trust(self):
        return self.params.get("disable_content_trust", False)

    @property
    def cache_dir(self):
        return Path(self.params['cache_dir']).expanduser()

    @property
    def cache_timeout(self):
        return self.params.get('cache_timeout', 604800)

    @property
    def content_trust(self):
        return self.params.get('content_trust', "notary")

    @property
    def cosign_path(self):
        return self.path.parent / "cosign"

    @property
    def notary_path(self):
        return self.cache_dir / "notary"

    @property
    def notary_trust_pinning(self):
        return self.params.get("trust_pinning", {})

    def get_server_info(self, hostname):
        remote_servers = self.params.get("remote_servers")
        if remote_servers:
            return remote_servers.get(hostname)
        return {}


def get_full_url(url, config):
    info = config.get_server_info(url.hostname)
    registry_url = info.get('registry')
    if registry_url is None:
        registry_url = unsplit_url("https", url.netloc)
    registry_url = parse_docker_url(registry_url)
    return unsplit_url(registry_url.scheme, registry_url.netloc, url.path, url.username, url.password)

def get_notary_url(url, config):
    info = config.get_server_info(url.hostname)
    notary_url = info.get('notary')
    if notary_url is None:
        registry_url = info.get('registry')
        if registry_url is None:
            registry_url = unsplit_url("https", url.netloc)
        notary_url = parse_docker_url(registry_url)
        port = 4443
    else:
        notary_url = parse_docker_url(notary_url)
        port = notary_url.port
    _, _, hostname = url.netloc.rpartition('@')
    hostname, _, _ = hostname.partition(':')
    path = f"{hostname}/{url.repository}"
    return unsplit_url(notary_url.scheme, notary_url.netloc, path, url.username, url.password, port=port)


class Store:
    def __init__(self, url, config=None, verify=None):
        url = parse_docker_url(url)
        self.url = url
        # 'docker://docker.io/library/alpine:latest'
        if url.scheme != "docker":
            raise ValueError("only docker://-url is supported")
        if config is None:
            config = ConcilConfig()
        if verify is None:
            verify = config.cafile
        self._cache_dir = config.cache_dir
        self._cache_timeout = config.cache_timeout

        if not url.username:
            url = complete_url_with_auth(url, config)
        full_url = get_full_url(url, config)
        logger.debug("full registry url: %s", full_url)
        self._hub = DockerHub(full_url, verify=verify)

        self._notary = self._cosign = None
        if config.disable_content_trust:
            pass
        elif config.content_trust == "cosign":
            from .cosign import Cosign
            self._cosign = Cosign(self._hub,
                config={"key_dir": config.cosign_path}
            )
        elif config.content_trust == "notary":
            full_url = get_notary_url(url, config)
            logger.debug("full notary url: %s", full_url)
            self._notary = Notary(full_url, config={
                "trust_dir" : config.notary_path,
                "trust_pinning": config.notary_trust_pinning,
            }, verify=verify)
        else:
            raise RuntimeError("unknown content trust")

    def cache_cleanup(self):
        cache_time = time.time() - self._cache_timeout
        to_be_removed = []
        for type in ['manifest', 'config', 'layers']:
            if (self._cache_dir / type).is_dir():
                for filename in (self._cache_dir / type).iterdir():
                    if filename.stat().st_mtime < cache_time:
                        logger.debug("unlink %s", filename)
                        to_be_removed.append(filename)
        for filename in to_be_removed:
            filename.unlink()

    def store_cache(self, type, bytes, digest=None):
        if digest is None:
            digest = hashlib.sha256(bytes).hexdigest()
        path = self._cache_dir / type
        path.mkdir(parents=True, exist_ok=True)
        logger.debug("storing %s/%s (%s bytes)", path, digest, len(bytes))
        (path / digest).write_bytes(bytes)

    def get_cache(self, type, digest):
        filename = self._cache_dir / type / digest
        logger.debug("trying cache %s", filename)
        bytes = filename.read_bytes()
        filename.touch()
        logger.debug("%s bytes read", len(bytes))
        return bytes

    def get_manifest(self, architecture=None, operating_system=None):
        if self._notary is None:
            manifest = self._hub.get_manifest(accept='application/vnd.docker.distribution.manifest.v2+json')
        else:
            hex_digest, target = self._notary.get_digest_for_tag(self.url.tag)
            try:
                manifest = self.get_cache("manifest", hex_digest)
            except FileNotFoundError:
                manifest = self._hub.get_manifest(hash=hex_digest, accept=None)
                if not check_hashes(manifest, target):
                    raise ValueError("hash check failed")
                self.store_cache("manifest", manifest, hex_digest)
        if self._cosign is not None:
            self._cosign.check_signature(manifest)
        manifest = json.loads(manifest)
        if manifest['mediaType'] == 'application/vnd.docker.distribution.manifest.list.v2+json':
            logger.debug("looking for manifest %s/%s", architecture, operating_system)
            for entry in manifest['manifests']:
                platform = entry['platform']
                logger.debug("found manifest for %s/%s", platform['architecture'], platform['os'])
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
                sq_filename = filename.with_suffix('.sq')
                with output_filename.open("rb") as stream:
                    diff_digest = convert(stream, sq_filename)
                sq_filename.rename(output_filename)
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
