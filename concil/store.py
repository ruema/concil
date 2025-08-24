import base64
import hashlib
import json
import logging
import os
import subprocess
import time
import urllib.parse
from gzip import GzipFile
from pathlib import Path

from .dockerhub import DockerHub, parse_docker_url
from .notary import Notary, check_hashes

logger = logging.getLogger(__name__)

TAR2SQFS = [
    os.path.join(os.path.dirname(__file__), "tar2sqfs"),
    "-c",
    "zstd",
    "-X",
    "level=10",
]


def unsplit_url(scheme, netloc, path=None, username=None, password=None, port=None):
    """Constructs a URL from its components.

    Args:
        scheme (str): The URL scheme.
        netloc (str): The network location.
        path (str, optional): The path. Defaults to None.
        username (str, optional): The username. Defaults to None.
        password (str, optional): The password. Defaults to None.
        port (int, optional): The port. Defaults to None.

    Returns:
        str: The constructed URL.
    """
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
        if path.startswith("/"):
            url += path
        else:
            url += f"/{path}"
    return url


def complete_url_with_auth(url, config):
    """Completes a URL with authentication information from the config.

    Args:
        url (urllib.parse.SplitResult): The URL to complete.
        config (ConcilConfig): The configuration object.

    Returns:
        urllib.parse.SplitResult: The completed URL.
    """
    repository = f"{url.hostname}{url.path}"
    auths = dict(config.params.get("auths", {}))

    # complete auths from environment
    for key in os.environ:
        if key.startswith("CONCIL_") and key.endswith("_REPO"):
            repo = os.environ[key]
            auth = os.environ.get(key.rsplit("_", 1)[0] + "_AUTH")
            if auth:
                auths[repo] = auth

    if repository in auths:
        auth = auths[repository]
    else:
        auth = None
        longest = 0
        for repo, repo_auth in auths.items():
            if (
                repo.endswith("*")
                and len(repo) > longest
                and repository.startswith(repo[:-1])
            ):
                longest = len(repo)
                auth = repo_auth
    if auth is None and url.hostname in auths:
        auth = auths[url.hostname]
    if auth is not None:
        auth = urllib.parse.quote_plus(
            base64.standard_b64decode(auth).decode(), safe=":"
        )
        url = url._replace(netloc=f"{auth}@{url.netloc}")
    return url


def copyfileobj(fsrc, fdst, length=16 * 1024):
    """Copies data from a file-like object to another.

    Args:
        fsrc: The source file-like object.
        fdst: The destination file-like object.
        length (int, optional): The chunk size. Defaults to 16 * 1024.
    """
    while True:
        buf = fsrc.read(length)
        if not buf:
            break
        fdst.write(buf)


def _convert_tar_to_squash(stream, output_filename):
    """Converts a tar stream to a squashfs file.

    Args:
        stream: The input tar stream.
        output_filename (str or Path): The path to the output squashfs file.

    Returns:
        str: The hex digest of the input tar stream.

    Raises:
        RuntimeError: If the conversion process fails.
    """
    digest = hashlib.sha256()
    process = subprocess.Popen(
        TAR2SQFS + ["-fq", str(output_filename)], stdin=subprocess.PIPE
    )
    while True:
        buf = stream.read(16 * 1024)
        if not buf:
            break
        digest.update(buf)
        process.stdin.write(buf)
    process.stdin.close()
    if process.wait():
        raise RuntimeError()
    return digest.hexdigest()


def convert_tar_gzip(stream, output_filename):
    """Converts a gzipped tar stream to a squashfs file.

    Args:
        stream: The input gzipped tar stream.
        output_filename (str or Path): The path to the output squashfs file.

    Returns:
        str: The hex digest of the input tar stream.
    """
    stream = GzipFile(fileobj=stream, mode="rb")
    return _convert_tar_to_squash(stream, output_filename)


def convert_tar(stream, output_filename):
    """Converts a tar stream to a squashfs file.

    Args:
        stream: The input tar stream.
        output_filename (str or Path): The path to the output squashfs file.

    Returns:
        str: The hex digest of the input tar stream.
    """
    return _convert_tar_to_squash(stream, output_filename)


IMAGE_CONVERTERS = {
    "application/vnd.docker.image.rootfs.diff.tar": convert_tar,
    "application/vnd.docker.image.rootfs.diff.tar.gzip": convert_tar_gzip,
    "application/vnd.oci.image.layer.v1.tar": convert_tar,
    "application/vnd.oci.image.layer.v1.tar+gzip": convert_tar_gzip,
    "tar": convert_tar,
    "tar+gzip": convert_tar_gzip,
}


CONFIG_PATH = "~/.concil/config.json"
CONFIG_PARAMS = {
    "cache_dir": "~/.concil",
    "cache_timeout": 604800,
    "disable_content_trust": False,
    "content_trust": "cosign",  # "notary"
    "remote_servers": {
        "docker.io": {
            "registry": "https://registry.hub.docker.com",
            "notary": "https://notary.docker.io",
        },
    },
}


class ConcilConfig:
    """Represents the concil configuration."""

    def __init__(self, config_path=None):
        """Initializes the configuration.

        Args:
            config_path (str or Path, optional): The path to the configuration
                file. If not provided, it is read from the CONCIL_CONFIG
                environment variable or defaults to CONFIG_PATH.
                Defaults to None.
        """
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
        """Path: The path to the CA file, if set."""
        if "cafile" in self.params:
            return Path(self.params["cafile"]).expanduser()
        return None

    @property
    def disable_content_trust(self):
        """bool: Whether content trust is disabled."""
        return self.params.get("disable_content_trust", False)

    @property
    def cache_dir(self):
        """Path: The path to the cache directory."""
        return Path(self.params["cache_dir"]).expanduser()

    @property
    def cache_timeout(self):
        """int: The cache timeout in seconds."""
        return self.params.get("cache_timeout", 604800)

    @property
    def content_trust(self):
        """str: The content trust provider to use ('cosign' or 'notary')."""
        return self.params.get("content_trust", "notary")

    @property
    def cosign_path(self):
        """Path: The path to the cosign directory."""
        return self.path.parent / "cosign"

    @property
    def notary_path(self):
        """Path: The path to the notary directory."""
        return self.cache_dir / "notary"

    @property
    def notary_trust_pinning(self):
        """dict: The notary trust pinning configuration."""
        return self.params.get("trust_pinning", {})

    def get_server_info(self, hostname):
        """Gets server information for a given hostname.

        Args:
            hostname (str): The hostname to get information for.

        Returns:
            dict: The server information.
        """
        remote_servers = self.params.get("remote_servers")
        if remote_servers:
            return remote_servers.get(hostname)
        return {}


def get_full_url(url, config):
    """Gets the full registry URL for a given Docker URL.

    Args:
        url (urllib.parse.SplitResult): The Docker URL.
        config (ConcilConfig): The configuration object.

    Returns:
        str: The full registry URL.
    """
    info = config.get_server_info(url.hostname)
    if info is None or info.get("registry") is None:
        registry_url = parse_docker_url(unsplit_url("https", url.netloc))
    else:
        registry_url = parse_docker_url(info.get("registry"))
    return unsplit_url(
        registry_url.scheme, registry_url.netloc, url.path, url.username, url.password
    )


def get_notary_url(url, config):
    """Gets the notary URL for a given Docker URL.

    Args:
        url (urllib.parse.SplitResult): The Docker URL.
        config (ConcilConfig): The configuration object.

    Returns:
        str: The notary URL.
    """
    info = config.get_server_info(url.hostname)
    if info is None or info.get("notary") is None:
        if info.get("registry") is None:
            notary_url = parse_docker_url(unsplit_url("https", url.netloc))
        else:
            notary_url = parse_docker_url(info.get("registry"))
        port = 4443
    else:
        notary_url = parse_docker_url(info.get("notary"))
        port = notary_url.port
    _, _, hostname = url.netloc.rpartition("@")
    hostname, _, _ = hostname.partition(":")
    path = f"{hostname}/{url.repository}"
    return unsplit_url(
        notary_url.scheme,
        notary_url.netloc,
        path,
        url.username,
        url.password,
        port=port,
    )


class Store:
    """A store for container images, handling caching and content trust."""

    def __init__(self, url, config=None, verify=None):
        """Initializes the store.

        Args:
            url (str): The Docker URL of the image.
            config (ConcilConfig, optional): The configuration object.
                If not provided, a default one is created. Defaults to None.
            verify (bool or str, optional): Whether to verify SSL certificates.
                Defaults to None.
        """
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

            self._cosign = Cosign(self._hub, config={"key_dir": config.cosign_path})
        elif config.content_trust == "notary":
            full_url = get_notary_url(url, config)
            logger.debug("full notary url: %s", full_url)
            self._notary = Notary(
                full_url,
                config={
                    "trust_dir": config.notary_path,
                    "trust_pinning": config.notary_trust_pinning,
                },
                verify=verify,
            )
        else:
            raise RuntimeError("unknown content trust")

    def cache_cleanup(self):
        """Removes expired files from the cache."""
        cache_time = time.time() - self._cache_timeout
        to_be_removed = []
        for type in ["manifest", "config", "layers"]:
            if (self._cache_dir / type).is_dir():
                for filename in (self._cache_dir / type).iterdir():
                    if filename.stat().st_mtime < cache_time:
                        logger.debug("unlink %s", filename)
                        to_be_removed.append(filename)
        for filename in to_be_removed:
            filename.unlink()

    def store_cache(self, type, bytes, digest=None):
        """Stores data in the cache.

        Args:
            type (str): The type of data to store (e.g., 'manifest', 'config').
            bytes (bytes): The data to store.
            digest (str, optional): The hex digest of the data. If not
                provided, it is calculated. Defaults to None.
        """
        if digest is None:
            digest = hashlib.sha256(bytes).hexdigest()
        path = self._cache_dir / type
        path.mkdir(parents=True, exist_ok=True)
        logger.debug("storing %s/%s (%s bytes)", path, digest, len(bytes))
        (path / digest).write_bytes(bytes)

    def get_cache(self, type, digest):
        """Gets data from the cache.

        Args:
            type (str): The type of data to get.
            digest (str): The hex digest of the data.

        Returns:
            bytes: The cached data.
        """
        filename = self._cache_dir / type / digest
        logger.debug("trying cache %s", filename)
        bytes = filename.read_bytes()
        filename.touch()
        logger.debug("%s bytes read", len(bytes))
        return bytes

    def get_manifest(self, architecture=None, operating_system=None):
        """Gets the image manifest.

        Args:
            architecture (str, optional): The desired architecture.
                Defaults to None.
            operating_system (str, optional): The desired operating system.
                Defaults to None.

        Returns:
            dict: The image manifest.
        """
        if self._notary is None:
            manifest = self._hub.get_manifest(
                accept="application/vnd.docker.distribution.manifest.v2+json"
            )
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
        if (
            manifest["mediaType"]
            == "application/vnd.docker.distribution.manifest.list.v2+json"
        ):
            logger.debug("looking for manifest %s/%s", architecture, operating_system)
            for entry in manifest["manifests"]:
                platform = entry["platform"]
                logger.debug(
                    "found manifest for %s/%s", platform["architecture"], platform["os"]
                )
                if (
                    platform["architecture"] == architecture
                    and platform["os"] == operating_system
                ):
                    break
            else:
                raise ValueError("no matching platform found")
            filename = self._get_blob("manifest", entry)
            with filename.open("rb") as input:
                manifest = json.load(input)
        return manifest

    def _get_blob(self, type, entry):
        """Gets a blob from the cache or downloads it.

        Args:
            type (str): The type of the blob.
            entry (dict): The descriptor for the blob.

        Returns:
            Path: The path to the blob file.
        """
        filename = self._cache_dir / type / entry["digest"]
        logging.debug("trying cache %s", filename)
        if filename.is_file():
            filename.touch()
            filename = filename.resolve()
            filename.touch()
            return filename
        filename.parent.mkdir(parents=True, exist_ok=True)
        output_filename = filename.with_suffix(".out")
        try:
            with output_filename.open("xb") as output:
                if type == "manifest":
                    response = self._hub.open_manifest(
                        hash=entry["digest"], accept=None
                    )
                else:
                    response = self._hub.open_blob(entry["digest"])
                digest = hashlib.sha256()
                size = 0
                with response:
                    for chunk in response.iter_content(102400):
                        if not chunk:
                            break
                        output.write(chunk)
                        size += len(chunk)
                        digest.update(chunk)
            if "size" in entry and entry["size"] != size:
                raise ValueError("hash check failed")
            digest = digest.hexdigest()
            if f"sha256:{digest}" != entry["digest"]:
                raise ValueError("hash check failed")
            convert = IMAGE_CONVERTERS.get(entry["mediaType"])
            if convert is not None:
                sq_filename = filename.with_suffix(".sq")
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
                output_filename.unlink()  # TODO: Python3.8 missing_ok=True
            except FileNotFoundError:
                pass
        return filename.resolve()

    def get_config(self, entry):
        """Gets the image configuration.

        Args:
            entry (dict): The descriptor for the configuration.

        Returns:
            dict: The image configuration.
        """
        filename = self._get_blob("config", entry)
        with filename.open("rb") as input:
            return json.load(input)

    def get_layer(self, entry):
        """Gets an image layer.

        Args:
            entry (dict): The descriptor for the layer.

        Returns:
            Path: The path to the layer file.
        """
        return self._get_blob("layers", entry)
