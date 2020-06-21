import re
import urllib
import requests

class DockerHub(object):
    def __init__(self, url, username=None, password=None):
        if username is None:
            parts = urllib.parse.urlsplit(url)
            username = parts.username
            password = parts.password
            url = parts._replace(netloc=parts.hostname).geturl()
        else:
            username = urllib.quote_plus(username)
            password = urllib.quote_plus(password)
        self.auth = ('%s:%s' % (username, password)).encode('base64').strip().decode('ASCII')
        url = url.rstrip('/')
        if not url.endswith('v2'):
            url += '/v2'
        self.url = url + '/'
        self.session = requests.Session()
        self.session.proxies = {"https": ""}
        self.session.verify = False

    def check_login(self, response):
        if response.status_code != 401:
            return True
        self.session.headers.pop("authorization", None)
        www_authenticate = response.headers['Www-Authenticate']
        if not www_authenticate.startswith('Bearer'):
            raise RuntimeError()
        params = dict(re.findall('([a-z]+)="([^"]*)"', www_authenticate))
        response2 = self.session.get(params['realm'], params={"service": params["service"], "scope": params["scope"]}, headers={"Authorization": "Basic %s" % self.auth})
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

    def post_blob(self, name, filename):
        response = self.request("POST", self.url + name + "/blobs/uploads/")
        location = response.headers['Location']
        with open(filename, 'rb') as inp:
            data = inp.read()
        reponse = self.session.put(location + "&digest=sha256:" + filename, headers={"Content-Type": "application/octet-stream"}, data=data)
        if response.status_code != 202:
            raise RuntimeError()
        return response

    def post_manifest(self, name, tag, filename):
        with open(filename, 'rb') as inp:
            data = inp.read()
        return self.request("PUT", self.url + name + "/manifests/" + tag, data=data, headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"})

    def get_manifest(self, name, tag):
        response = self.request("GET", self.url + name + "/manifests/" + tag, headers={"Accept": "application/vnd.docker.distribution.manifest.v2+json"})
        return response.content

    def get_blob(self, name, digest):
        response = self.request("GET", self.url + name + "/blobs/" + digest)
        return response.content

