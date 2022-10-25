import os
import re
import urllib
import requests
import base64
import getpass

def base64url_encode(payload):
    if not isinstance(payload, bytes):
        payload = payload.encode('utf-8')
    encode = base64.urlsafe_b64encode(payload)
    return encode.decode('utf-8') #.rstrip('=') Harbor don't like stripped base64

class DockerSplitResult(urllib.parse.SplitResult):
    __slots__ = ()

    @property
    def repository(self):
        repository, _, tag = self.path.partition(":")
        return repository[1:] # strip /

    @property
    def tag(self):
        repository, _, tag = self.path.partition(":")
        return tag or "latest"
    
    @property
    def url(self):
        if self.scheme not in ('https', 'http', 'docker', 'store'):
            raise ValueError("url must be a docker://-Url")
        scheme = self.scheme if self.scheme == 'http' else 'https'
        if self.port:
            netloc = f"{self.hostname}:{self.port}"
        else:
            netloc = self.hostname
        return urllib.parse.urlunsplit((scheme, netloc, 'v2/' + self.repository, '', ''))    


def parse_docker_url(docker_url):
    return DockerSplitResult(*urllib.parse.urlsplit(docker_url))


class ResponseStream(object):
    def __init__(self, response):
        self._response = response
        self._iterator = response.iter_content(65536)
        self._buf = b""

    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self.close()

    def close(self):
        self._response.close()

    def read(self, size=None):
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
    def __init__(self, hub, digest=None):
        self.hub = hub
        self.digest = digest
    
    def __truediv__(self, digest):
        return DockerPath(self.hub, digest)

    def read_bytes(self):
        with self.hub.open_blob('sha256:' + self.digest) as file:
            return file.content

    def open(self, mode='rb'):
        if mode != 'rb':
            raise ValueError("mode have to be 'rb'")
        return ResponseStream(self.hub.open_blob('sha256:' + self.digest))


class DockerHub(object):
    def __init__(self, docker_url, verify=None):
        parts = parse_docker_url(docker_url)
        self.username = urllib.parse.unquote_plus(parts.username) if parts.username else None
        self.password = urllib.parse.unquote_plus(parts.password) if parts.password else None
        self.repository = parts.repository
        self.url = parts.url
        self.tag = parts.tag
        self.session = requests.Session()
        self.session.proxies = {"https": ""}
        self.session.verify = verify
        self.session.headers['Docker-Distribution-Api-Version'] = 'registry/2.0'

    def check_login(self, response):
        if response.status_code != 401:
            return True
        print(response.headers)
        self.session.headers.pop("authorization", None)
        www_authenticate = response.headers['Www-Authenticate']
        if not www_authenticate.startswith('Bearer'):
            raise RuntimeError()
        params = dict(re.findall('([a-z]+)="([^"]*)"', www_authenticate))
        if not self.username:
            self.username = input("Username for storage:")
        if not self.password:
            self.password = getpass.getpass("Password for storage:")
        auth = '%s:%s' % (self.username, self.password)
        auth = base64url_encode(auth)
        realm = params.pop('realm')
        response2 = self.session.get(realm,
            params=params,
            headers={"Authorization": "Basic %s" % auth} if self.username else {}
        )
        response2.raise_for_status()
        token = response2.json()['token']
        self.session.headers["Authorization"] = "Bearer " + token
        return False
    
    def request(self, method, url, **kw):
        print(url)
        response = self.session.request(method, url, **kw)
        print(response.headers)
        if not self.check_login(response):
            response = self.session.request(method, url, **kw)
            print(response.headers)
        response.raise_for_status()
        return response

    def post_blob(self, filename):
        self.session.cookies.clear()
        response = self.request("POST", self.url + "/blobs/uploads/")
        location = response.headers['Location']
        with open(filename, 'rb') as input:
            self.session.cookies.clear()
            response = self.session.put(location,
                params={"digest": "sha256:" + os.path.basename(filename)},
                headers={"Content-Type": "application/octet-stream"},
                data=input)
        if response.status_code != 201:
            raise RuntimeError(response.text)
        return response

    def post_blob_data(self, data, digest):
        self.session.cookies.clear()
        response = self.request("POST", self.url + "/blobs/uploads/")
        location = response.headers['Location']
        self.session.cookies.clear()
        response = self.session.put(location,
            params={"digest": "sha256:" + digest},
            headers={"Content-Type": "application/octet-stream"},
            data=data)
        if response.status_code != 201:
            raise RuntimeError(response.text)
        return response

    def post_manifest(self, data, tag=None, content_type="application/vnd.docker.distribution.manifest.v2+json"):
        self.session.cookies.clear()
        if tag is None:
            tag = self.tag
        return self.request("PUT", self.url + "/manifests/" + tag,
            headers={"Content-Type": content_type},
            data=data,
        )

    def open_blob(self, digest):
        response = self.request("GET", self.url + "/blobs/" + digest, stream=True)
        response.raise_for_status()
        return response

    def has_blob(self, digest):
        try:
            _ = self.request("HEAD", self.url + "/blobs/" + digest)
        except requests.HTTPError as error:
            if error.response.status_code == 404:
                return False
            raise
        return True

    def open_manifest(self, hash=None, accept="application/vnd.docker.distribution.manifest.v1+json"):
        headers = {"Accept": accept} if accept else {}
        tag = self.tag if not hash else hash
        response = self.request("GET", self.url + "/manifests/" + tag, headers=headers, stream=True)
        return response

    def get_manifest(self, hash=None, accept="application/vnd.docker.distribution.manifest.v1+json"):
        response = self.open_manifest(hash, accept)
        return response.content
