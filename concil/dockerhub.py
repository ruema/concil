import re
import urllib
import requests
import base64
import getpass
from jwcrypto.common import base64url_decode, base64url_encode

class DockerHub(object):
    def __init__(self, docker_url, verify=None):
        docker_url = urllib.parse.urlsplit(docker_url)
        if docker_url.scheme not in ('https', 'http', 'docker', 'store'):
            raise ValueError("url must be a docker://-Url")
        self.username = docker_url.username
        self.password = docker_url.password
        repository, _, tag = docker_url.path.partition(":")
        if docker_url.port:
            netloc = f"{docker_url.hostname}:{docker_url.port}"
        else:
            netloc = docker_url.hostname
        scheme = docker_url.scheme if docker_url.scheme == 'http' else 'https'
        self.repository = repository[1:] # strip /
        self.url = urllib.parse.urlunsplit((scheme, netloc, 'v2' + repository,'',''))
        self.tag = tag or "latest"
        self.session = requests.Session()
        self.session.proxies = {"https": ""}
        self.session.verify = verify

    def check_login(self, response):
        if response.status_code != 401:
            return True
        self.session.headers.pop("authorization", None)
        www_authenticate = response.headers['Www-Authenticate']
        if not www_authenticate.startswith('Bearer'):
            raise RuntimeError()
        params = dict(re.findall('([a-z]+)="([^"]*)"', www_authenticate))
        if not self.username:
            self.username = urllib.parse.quote_plus(input("Username for storage:"))
        if not self.password:
            self.password = urllib.parse.quote_plus(getpass.getpass("Password for storage:"))
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
        response = self.session.request(method, url, **kw)
        if not self.check_login(response):
            response = self.session.request(method, url, **kw)
        response.raise_for_status()
        return response

    def post_blob(self, filename):
        response = self.request("POST", self.url + "/blobs/uploads/")
        location = response.headers['Location']
        with open(filename, 'rb') as input:
            reponse = self.session.put(location,
                params={"digest": "sha256:" + filename},
                headers={"Content-Type": "application/octet-stream"},
                data=input)
        if response.status_code != 202:
            raise RuntimeError()
        return response

    def post_manifest(self, filename):
        with open(filename, 'rb') as inp:
            data = inp.read()
        return self.request("PUT", self.url + "/manifests/" + self.tag,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
            data=data,
        )

    def open_blob(self, digest):
        return self.request("GET", self.url + "/blobs/" + digest, stream=True)

    def get_manifest(self):
        response = self.request("GET", self.url + "/manifests/" + self.tag,
            headers={"Accept": "application/vnd.docker.distribution.manifest.v2+json"})
        return response.content

