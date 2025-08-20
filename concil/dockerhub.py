import base64
import getpass
import logging
import os
import re
import urllib

import requests

logger = logging.getLogger(__file__)


def base64url_encode(payload):
    """Encodes a payload in base64url format.

    Args:
        payload (bytes or str): The payload to encode. If it's a string, it will
            be encoded to UTF-8 bytes.

    Returns:
        str: The base64url-encoded payload.
    """
    if not isinstance(payload, bytes):
        payload = payload.encode("utf-8")
    encode = base64.urlsafe_b64encode(payload)
    return encode.decode("utf-8")  # .rstrip('=') Harbor don't like stripped base64


class DockerSplitResult(urllib.parse.SplitResult):
    """A urllib.parse.SplitResult subclass for Docker URLs.

    This class adds Docker-specific properties to the result of a URL split,
    such as `repository` and `tag`.
    """

    __slots__ = ()

    @property
    def repository(self):
        """str: The repository part of the Docker URL."""
        repository, _, tag = self.path.partition(":")
        return repository[1:]  # strip /

    @property
    def tag(self):
        """str: The tag part of the Docker URL, defaulting to 'latest'."""
        repository, _, tag = self.path.partition(":")
        return tag or "latest"

    @property
    def url(self):
        """str: The full URL for the Docker registry API."""
        if self.scheme not in ("https", "http", "docker", "store"):
            raise ValueError("url must be a docker://-Url")
        scheme = self.scheme if self.scheme == "http" else "https"
        if self.port:
            netloc = f"{self.hostname}:{self.port}"
        else:
            netloc = self.hostname
        return urllib.parse.urlunsplit(
            (scheme, netloc, "v2/" + self.repository, "", "")
        )


def parse_docker_url(docker_url):
    """Parses a Docker URL.

    Args:
        docker_url (str): The Docker URL to parse.

    Returns:
        DockerSplitResult: The parsed Docker URL.
    """
    return DockerSplitResult(*urllib.parse.urlsplit(docker_url))


class ResponseStream(object):
    """A file-like object for streaming HTTP responses.

    Args:
        response (requests.Response): The response object to stream.
    """

    def __init__(self, response):
        self._response = response
        self._iterator = response.iter_content(65536)
        self._buf = b""

    def __enter__(self):
        """Enters the context manager."""
        return self

    def __exit__(self, *args):
        """Exits the context manager and closes the response."""
        self.close()

    def close(self):
        """Closes the underlying response."""
        self._response.close()

    def read(self, size=None):
        """Reads from the response stream.

        Args:
            size (int, optional): The number of bytes to read. If not specified,
                reads the entire stream. Defaults to None.

        Returns:
            bytes: The bytes read from the stream.
        """
        if size is None:
            result = [self._buf]
            result.extend(self._iterator)
            return b"".join(result)
        else:
            result = self._buf
            while len(result) < size:
                try:
                    result += next(self._iterator)
                except StopIteration:
                    break
            self._buf = result[size:]
            return result[:size]


class DockerPath(object):
    """Represents a path to a blob in a Docker registry.

    Args:
        hub (DockerHub): The DockerHub instance to use for communication.
        digest (str, optional): The digest of the blob. Defaults to None.
    """

    def __init__(self, hub, digest=None):
        self.hub = hub
        self.digest = digest

    def __truediv__(self, digest):
        """Creates a new DockerPath with a digest.

        Args:
            digest (str): The digest of the blob.

        Returns:
            DockerPath: A new DockerPath instance.
        """
        return DockerPath(self.hub, digest)

    def read_bytes(self):
        """Reads the entire content of the blob.

        Returns:
            bytes: The content of the blob.
        """
        with self.hub.open_blob("sha256:" + self.digest) as file:
            return file.content

    def open(self, mode="rb"):
        """Opens the blob for reading.

        Args:
            mode (str, optional): The mode to open the file in. Must be 'rb'.
                Defaults to "rb".

        Returns:
            ResponseStream: A file-like object for the blob.

        Raises:
            ValueError: If the mode is not 'rb'.
        """
        if mode != "rb":
            raise ValueError("mode have to be 'rb'")
        return ResponseStream(self.hub.open_blob("sha256:" + self.digest))


class DockerHub(object):
    """A client for interacting with a Docker registry.

    Args:
        docker_url (str): The URL of the Docker registry.
        verify (bool, optional): Whether to verify SSL certificates.
            Defaults to None.
    """

    def __init__(self, docker_url, verify=None):
        parts = parse_docker_url(docker_url)
        self.username = (
            urllib.parse.unquote_plus(parts.username)
            if parts.username is not None
            else None
        )
        self.password = (
            urllib.parse.unquote_plus(parts.password)
            if parts.password is not None
            else None
        )
        self.repository = parts.repository
        self.url = parts.url
        self.tag = parts.tag
        self.session = requests.Session()
        self.session.proxies = {"https": ""}
        self.session.verify = verify
        self.session.headers["Docker-Distribution-Api-Version"] = "registry/2.0"

    def check_login(self, response):
        """Checks if a login is required and performs it if necessary.

        Args:
            response (requests.Response): The response to check.

        Returns:
            bool: True if the request was successful without a new login,
                False otherwise.

        Raises:
            RuntimeError: If the authentication method is not 'Bearer'.
        """
        if response.status_code != 401:
            return True
        logger.debug(response.headers)
        self.session.headers.pop("authorization", None)
        www_authenticate = response.headers["Www-Authenticate"]
        if not www_authenticate.startswith("Bearer"):
            raise RuntimeError()
        params = dict(re.findall('([a-z]+)="([^"]*)"', www_authenticate))
        if self.username is None:
            self.username = input("Username for storage:")
        if self.password is None:
            self.password = getpass.getpass("Password for storage:")
        auth = "%s:%s" % (self.username, self.password)
        auth = base64url_encode(auth)
        realm = params.pop("realm")
        response2 = self.session.get(
            realm,
            params=params,
            headers={"Authorization": "Basic %s" % auth} if self.username else {},
        )
        response2.raise_for_status()
        token = response2.json()["token"]
        self.session.headers["Authorization"] = "Bearer " + token
        return False

    def request(self, method, url, **kw):
        """Sends a request to the Docker registry.

        Args:
            method (str): The HTTP method to use.
            url (str): The URL to send the request to.
            **kw: Additional keyword arguments to pass to the request.

        Returns:
            requests.Response: The response from the registry.

        Raises:
            RuntimeError: If the request fails.
        """
        logger.info("%s %s", method, url)
        response = self.session.request(method, url, **kw)
        logger.debug(response.headers)
        if not self.check_login(response):
            response = self.session.request(method, url, **kw)
            logger.debug(response.headers)
        if response.status_code // 100 != 2:
            try:
                errors = response.json()["errors"]
                errors = "\n".join(
                    error["code"] + ": " + error["message"] for error in errors
                )
            except Exception:
                response.raise_for_status()
            else:
                raise RuntimeError(
                    f"Status: {response.status_code} Url: {url}\n{errors}"
                )
        return response

    def post_blob(self, filename):
        """Uploads a blob from a file.

        Args:
            filename (str): The path to the file to upload.

        Returns:
            requests.Response: The response from the registry.

        Raises:
            RuntimeError: If the upload fails.
        """
        self.session.cookies.clear()
        response = self.request("POST", self.url + "/blobs/uploads/")
        location = response.headers["Location"]
        with open(filename, "rb") as input:
            self.session.cookies.clear()
            response = self.session.put(
                location,
                params={"digest": "sha256:" + os.path.basename(filename)},
                headers={"Content-Type": "application/octet-stream"},
                data=input,
            )
        if response.status_code != 201:
            raise RuntimeError(response.text)
        return response

    def post_blob_data(self, data, digest):
        """uploads the data with the given digest of format "sha256:1234...".

        Args:
            data (bytes): The data to upload.
            digest (str): The digest of the data, in the format "sha256:...".

        Returns:
            requests.Response: The response from the registry.

        Raises:
            RuntimeError: If the upload fails.
        """
        self.session.cookies.clear()
        response = self.request("POST", self.url + "/blobs/uploads/")
        location = response.headers["Location"]
        self.session.cookies.clear()
        response = self.session.put(
            location,
            params={"digest": digest},
            headers={"Content-Type": "application/octet-stream"},
            data=data,
        )
        if response.status_code != 201:
            raise RuntimeError(response.text)
        return response

    def post_manifest(
        self,
        data,
        tag=None,
        content_type="application/vnd.docker.distribution.manifest.v2+json",
    ):
        """Uploads a manifest.

        Args:
            data (bytes): The manifest data.
            tag (str, optional): The tag for the manifest. If not specified, the
                tag from the Docker URL is used. Defaults to None.
            content_type (str, optional): The content type of the manifest.
                Defaults to "application/vnd.docker.distribution.manifest.v2+json".

        Returns:
            requests.Response: The response from the registry.
        """
        self.session.cookies.clear()
        if tag is None:
            tag = self.tag
        return self.request(
            "PUT",
            self.url + "/manifests/" + tag,
            headers={"Content-Type": content_type},
            data=data,
        )

    def open_blob(self, digest):
        """Opens a blob for reading.

        Args:
            digest (str): The digest of the blob to open.

        Returns:
            requests.Response: The response object for the blob, which can be
                used for streaming.
        """
        response = self.request("GET", self.url + "/blobs/" + digest, stream=True)
        response.raise_for_status()
        return response

    def has_blob(self, digest):
        """Checks if a blob exists in the registry.

        Args:
            digest (str): The digest of the blob to check.

        Returns:
            bool: True if the blob exists, False otherwise.
        """
        try:
            _ = self.request("HEAD", self.url + "/blobs/" + digest)
        except requests.HTTPError as error:
            if error.response.status_code == 404:
                return False
            raise
        return True

    def open_manifest(
        self, hash=None, accept="application/vnd.docker.distribution.manifest.v1+json"
    ):
        """Opens a manifest for reading.

        Args:
            hash (str, optional): The hash of the manifest to open. If not
                specified, the tag from the Docker URL is used. Defaults to None.
            accept (str, optional): The `Accept` header to use for the request.
                Defaults to "application/vnd.docker.distribution.manifest.v1+json".

        Returns:
            requests.Response: The response object for the manifest, which can be
                used for streaming.
        """
        headers = {"Accept": accept} if accept else {}
        tag = self.tag if not hash else hash
        response = self.request(
            "GET", self.url + "/manifests/" + tag, headers=headers, stream=True
        )
        return response

    def get_manifest(
        self, hash=None, accept="application/vnd.docker.distribution.manifest.v1+json"
    ):
        """Gets the content of a manifest.

        Args:
            hash (str, optional): The hash of the manifest to get. If not
                specified, the tag from the Docker URL is used. Defaults to None.
            accept (str, optional): The `Accept` header to use for the request.
                Defaults to "application/vnd.docker.distribution.manifest.v1+json".

        Returns:
            bytes: The content of the manifest.
        """
        response = self.open_manifest(hash, accept)
        return response.content
