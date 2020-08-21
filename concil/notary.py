import re
import json
import hashlib
import datetime
import dateutil.parser
import urllib.parse
from pathlib import Path
from getpass import getpass
from jwcrypto.common import base64url_decode, base64url_encode
from base64 import standard_b64encode, b64decode
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from cryptography.hazmat.primitives.serialization import load_der_public_key, load_der_private_key, Encoding, PublicFormat, PrivateFormat, BestAvailableEncryption
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, SignatureAlgorithmOID
from cryptography import x509
from .dockerhub import DockerHub
import logging
logger = logging.getLogger(__name__)

def verify_cert(cert, public_key):
    if cert.signature_algorithm_oid in (
        SignatureAlgorithmOID.RSA_WITH_MD5, SignatureAlgorithmOID.RSA_WITH_SHA1,
        SignatureAlgorithmOID._RSA_WITH_SHA1, SignatureAlgorithmOID.RSA_WITH_SHA224,
        SignatureAlgorithmOID.RSA_WITH_SHA256, SignatureAlgorithmOID.RSA_WITH_SHA384,
        SignatureAlgorithmOID.RSA_WITH_SHA512,
    ):
        public_key.verify(cert.signature, cert.tbs_certificate_bytes,
            padding.PSS(mgf=padding.MGF1(cert.signature_hash_algorithm), salt_length=padding.PSS.MAX_LENGTH),
            cert.signature_hash_algorithm)
    elif cert.signature_algorithm_oid in (
        SignatureAlgorithmOID.ECDSA_WITH_SHA1, SignatureAlgorithmOID.ECDSA_WITH_SHA224,
        SignatureAlgorithmOID.ECDSA_WITH_SHA256, SignatureAlgorithmOID.ECDSA_WITH_SHA384,
        SignatureAlgorithmOID.ECDSA_WITH_SHA512,
    ):
        public_key.verify(cert.signature, cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm))
    elif cert.signature_algorithm_oid in (
        SignatureAlgorithmOID.DSA_WITH_SHA1,
        SignatureAlgorithmOID.DSA_WITH_SHA224,
        SignatureAlgorithmOID.DSA_WITH_SHA256,
    ):
        public_key.verify(cert.signature, cert.tbs_certificate_bytes, cert.signature_hash_algorithm)
    elif cert.signature_algorithm_oid in (
        SignatureAlgorithmOID.ED25519,
        SignatureAlgorithmOID.ED448,
    ):
        public_key.verify(cert.signature, cert.tbs_certificate_bytes)
    else:
        raise RuntimeError("unknown signature algorithm")


def parse_outer_dict(data):
    parts = iter(re.findall(rb'"(?:[^"]|\\")*"|[{}\[\]]|[^{}\[\]"]+', data))
    if next(parts) != b'{':
        raise ValueError('"{" expected.')
    result = {}
    while True:
        key = next(parts)
        if not key.strip():
            continue
        if key[0] != 34: # b'"'
            raise ValueError('string expected')
        if next(parts).strip() != b':':
            raise ValueError('":" expected.')
        count = 0
        value = b""
        while True:
            token = next(parts)
            if token in (b'}', b']'):
                count -= 1
            elif token in (b'{', b'['):
                count += 1
            value += token
            if count == 0:
                break
        result[key] = value
        token = next(parts)
        if token == b'}':
            break
        if token.strip() != b',':
            raise ValueError('"}" expected.')
    if list(parts):
        raise ValueError("eom expected")
    return result


def verify_ecdsa(public_key, data, sig):
    key_size = (public_key.key_size + 7) // 8
    r = int.from_bytes(sig[:key_size], 'big')
    s = int.from_bytes(sig[key_size:], 'big')
    public_key.verify(encode_dss_signature(r,s), data, ec.ECDSA(hashes.SHA256()))

def sign_ecdsa(private_key, data):
    key_size = (private_key.key_size + 7) // 8
    sig = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    r,s = decode_dss_signature(sig)
    return r.to_bytes(key_size, 'big') + s.to_bytes(key_size, 'big')

def verify_rsapss(public_key, data, sig):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    public_key.verify(sig, data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
        salt_length=32), hashes.SHA256())

def sign_rsapss(private_key, data):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    return private_key.sign(data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=32
        ),
        hashes.SHA256()
    )

SIGNATURE_METHODS = {
    "ecdsa": verify_ecdsa,
    'rsapss': verify_rsapss,
}

def decode_signed_json(public_keys, data, min_version=0):
    result = parse_outer_dict(data)
    signatures = json.loads(result[b'"signatures"'])
    signed = result[b'"signed"']
    for signature in signatures:
        key = public_keys[signature['keyid']]['public_key']
        sig = base64url_decode(signature['sig'])
        method = signature['method']
        SIGNATURE_METHODS[method](key, signed, sig)
    result = json.loads(signed)
    if dateutil.parser.parse(result['expires']) < datetime.datetime.now().astimezone():
        raise RuntimeError("invalid")
    if result['version'] < min_version:
        raise RuntimeError("invalid")
    return result

def encode_json(data):
    return json.dumps(data, separators=(',',':'), sort_keys=True).encode('utf8')

def encode_signed_json(private_keys, data):
    data = encode_json(data)
    signatures = []
    for key_id, key in private_keys.items():
        sig = sign_ecdsa(key, data)
        signatures.append({
            "keyid": key_id,
            "method": "ecdsa",
            "sig": standard_b64encode(sig).decode('utf8')
        })
    signatures = encode_json(signatures)
    return b'{"signed":%s,"signatures":%s}' % (data, signatures)


class PrivateKeyStore(object):
    def __init__(self, path):
        self.path = Path(path).expanduser()
        self.root = None
        self.keys = {}

    def _generate_key(self):
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        keyval = key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        key_dict = {
            "keytype": "ecdsa",
            "keyval": {"private": None, "public": standard_b64encode(keyval).decode('utf8')}
        }
        key_id = hashlib.sha256(encode_json(key_dict)).hexdigest()
        return key, key_dict, key_id

    def get_root(self):
        if self.root is None:
            for filename in self.path.glob('*.key'):
                lines = filename.read_bytes().splitlines()
                if lines[1].strip().startswith(b'role:') and lines[1].split(b':', 1)[1].strip() == b'root':
                    self.root = self.get(filename.stem, "root")
                    break
            else:
                self.root, _, _ = self.generate_key("root", None)
        return self.root

    def generate_key(self, key_type, repository):
        key, key_dict, key_id = self._generate_key()
        while True:
            print(f"Enter passphrase for new {key_type} key with ID {key_id[:7]}:")
            password = getpass()
            print(f"Repeat passphrase for new {key_type} key with ID {key_id[:7]}:")
            password_confirm = getpass()
            if password == password_confirm:
                break
            print("Passwords differ.")
        data = key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, BestAvailableEncryption(password.encode('utf8')))
        (self.path / f'{key_id}.key').write_bytes(
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n" +
            ("gun: %s\n" % repository if repository else "").encode('utf8') +
            ("role: %s\n" % key_type).encode('utf8') +
            (b"\n%s" % base64.encodebytes(data)) +
            b"-----END ENCRYPTED PRIVATE KEY-----\n")
        self.keys[key_id] = key
        return key, key_dict, key_id

    def get(self, key_id, key_type):
        if key_id not in self.keys:
            try:
                lines = (self.path / f'{key_id}.key').read_bytes().splitlines()
            except FileNotFoundError:
                raise KeyError(key_id)
            if lines[0] != b"-----BEGIN ENCRYPTED PRIVATE KEY-----":
                raise RuntimeError("invalid key file")
            if lines[-1] != b"-----END ENCRYPTED PRIVATE KEY-----":
                raise RuntimeError("invalid key file")
            # skip header
            i = len(lines) - 1
            while i>1 and lines[i].strip() and b':' not in lines[i]:
                i -= 1
            key_data = b''.join(lines[i:-1])
            print(f"Enter passphrase for {key_type} key with ID {key_id[:7]}:")
            password = getpass()
            self.keys[key_id] = load_der_private_key(base64.decodebytes(key_data), password.encode('utf8'), default_backend())
        return self.keys[key_id]

def load_key(key):
    if key['keytype'] in ['ecdsa-x509', 'rsa-x509']:
        data = base64url_decode(key['keyval']['public'])
        cert = x509.load_pem_x509_certificate(data, backend=default_backend())
        return cert.public_key()
    else:
        data = base64url_decode(key['keyval']['public'])
        return load_der_public_key(data, backend=default_backend())

HASH_ALGORITHMS = {
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}

def check_hashes(bytes, hashes):
    if "length" in hashes and len(bytes) != hashes['length']:
        return False
    hash_found = False
    for hash_name, hash_function in HASH_ALGORITHMS.items():
        if hash_name in hashes["hashes"]:
            hash_found = True
            if hash_function(bytes).digest() != base64url_decode(hashes["hashes"][hash_name]):
                return False
    return hash_found

class Metafile(object):
    def __init__(self, bytes):
        self.bytes = bytes
        self.data = json.loads(bytes)

    def version(self):
        return self.data['signed']['version']

    def expires(self):
        return dateutil.parser.parse(self.data['signed']['expires'])

    def hash(self):
        return hashlib.sha256(self.bytes).hexdigest()

    def check_hashes(self, hashes):
        return check_hashes(self.bytes, hashes)

    def verify_sign(self, root):
        public_keys = root.get_keys(self.name)
        result = parse_outer_dict(self.bytes)
        signatures = self.data["signatures"]
        if not signatures:
            raise RuntimeError("no signature found")
        signatures = [s for s in signatures if s['keyid'] in public_keys]
        if not signatures:
            raise RuntimeError("no key found for signatures")
        signed = result[b'"signed"']
        for signature in signatures:
            key = load_key(public_keys[signature['keyid']])
            sig = base64url_decode(signature['sig'])
            method = signature['method']
            SIGNATURE_METHODS[method](key, signed, sig)


class Timestamp(Metafile):
    name = "timestamp"

    def __getitem__(self, value):
        return self.data['signed']['meta'][value]

class Snapshot(Metafile):
    name = "snapshot"

    def __getitem__(self, value):
        return self.data['signed']['meta'][value]

class Root(Metafile):
    name = "root"

    def get_keys(self, role):
        roles = self.data['signed']['roles']
        keys = self.data['signed']['keys']
        keyids = roles[role]['keyids']
        return {k: keys[k] for k in keyids}

    def verify_trust_pinning(self, config):
        if "trust_pinning" not in config:
            # without trust_pinning, verification succeeds always
            return
        trust_pinning = config["trust_pinning"]
        if "certs" in trust_pinning:
            certs = trust_pinning["certs"]
            if store._hub.repository in certs:
                key_ids = certs[store._hub.repository]
                root_keys = root.get_keys('root')
                for key_id in key_ids:
                    if key_id in root_keys:
                        bytes = encode_json(root_keys[key_id])
                        hash256 = hashlib.sha256(bytes).digest()
                        if hash256 == base64.b16decode(key_id.upper()):
                            return
                raise RuntimeError("no valid key-id")
        if "ca" in trust_pinning:
            cas = trust_pinning["ca"]
            if store._hub.repository in ca:
                # TODO: implement ca validation
                raise NotImplementedError()
        if trust_pinning.get("disable_tofu", False):
            raise RuntimeError("tofu disabled")

class Targets(Metafile):
    name = "targets"

    def get_keys(self, role):
        roles = self.data['signed']['delegations']['roles']
        keys = self.data['signed']['delegations']['keys']
        keyids = next(r['keyids'] for r in roles if r['name'] == role)
        return {k: keys[k] for k in keyids}

    def __getitem__(self, target):
        return self.data['signed']['targets'][target]


class JsonStore(object):
    def __init__(self, path, url, config, verify=None):
        self.config = config
        self._hub = DockerHub(url, verify=verify)
        self.path = path / self._hub.repository

    def get(self, metafileclass, hashes=None, name=None):
        type = name or metafileclass.name
        filename = self.path / f"{type}.json"
        if hashes is not None:
            # look into cache
            try:
                bytes = filename.read_bytes()
            except FileNotFoundError:
                version = 0
                cached_metafile = None
            else:
                cached_metafile = metafileclass(bytes)
                bytes_hash = cached_metafile.hash()
                logger.info("Cached %s %s", type, bytes_hash)
                if cached_metafile.check_hashes(hashes):
                    return cached_metafile
                version = cached_metafile.version()
        else:
            version = 0
            cached_metafile = None
        if hashes is not None:
            hash = base64.b16encode(base64url_decode(hashes['hashes']['sha256'])).decode('ASCII').lower()
            url = f"{self._hub.url}/_trust/tuf/{type}.{hash}.json"
        else:
            url = f"{self._hub.url}/_trust/tuf/{type}.json"
        r = self._hub.request('GET', url)
        bytes = r.content
        metafile = metafileclass(bytes)
        if metafile.version() <= version:
            raise RuntimeError("Version too old %s < %s" % (version, metafile.version()))
        if metafile.expires() < datetime.datetime.now().astimezone():
            raise RuntimeError("expired")
        if hashes is not None and not metafile.check_hashes(hashes):
            raise RuntimeError()
        if type == 'root':
            if cached_metafile is not None:
                # check root signature with old root
                metafile.verify_sign(cached_metafile)
            else:
                metafile.verify_trust_pinning(self.config)
        filename.parent.mkdir(exist_ok=True, parents=True)
        filename.write_bytes(bytes)
        return metafile


def update_targets(delegate_targets, store, snapshot, targets):
    roles = targets.data['signed']['delegations']['roles']
    for role in roles:
        name = role['name']
        if name in delegate_targets:
            raise RuntimeError("duplicate delegation %s" % name)
        delegate = store.get(Targets, snapshot[name], name)
        delegate.name = name
        delegate.verify_sign(targets)
        delegate_targets[name] = delegate
        update_targets(delegate_targets, store, snapshot, delegate)


class Notary(object):
    CONFIG_PATH = "~/.notary/config.json"
    CONFIG_PARAMS = {
        "trust_dir" : "~/.notary",
        "remote_server": {
            "url": "https://notary.docker.io",
        },
    }

    def __init__(self, url, initialize=False, config=CONFIG_PATH):
        if not isinstance(config, dict):
            try:
                with Path(config).expanduser().open(encoding="utf8") as config_file:
                    config = json.load(config_file)
            except FileNotFoundError:
                config = self.CONFIG_PARAMS
        verify = None
        if 'remote_server' in config:
            if 'url' in config['remote_server']:
                url = urllib.parse.urljoin(config['remote_server']['url'], url)
            if 'root_ca' in config['remote_server']:
                verify = config['remote_server']['root_ca']
        self._trust_dir = Path(config['trust_dir']).expanduser()
        self._json_store = JsonStore(self._trust_dir / 'tuf', url, config, verify=verify)
        self._private_key_store = PrivateKeyStore(self._trust_dir / 'private')
        if initialize:
            pass
        else:
            store = self._json_store
            timestamp = store.get(Timestamp)
            snapshot = store.get(Snapshot, timestamp['snapshot'])
            root = store.get(Root, snapshot['root'])
            targets = store.get(Targets, snapshot['targets'])
            timestamp.verify_sign(root)
            snapshot.verify_sign(root)
            root.verify_sign(root)
            targets.verify_sign(root)
            delegate_targets = {}
            update_targets(delegate_targets, store, snapshot, targets)
            self.root = root
            self.targets = targets
            self.delegate_targets = delegate_targets
