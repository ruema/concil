import os
import json
import tempfile
import base64
import gzip
import subprocess
import shutil
import io
from hashlib import sha256, sha512
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from jwcrypto import jwk, jwe
from jwcrypto.common import base64url_decode, base64url_encode
from .store import IMAGE_CONVERTERS
from .dockerhub import DockerHub

class FormatError(Exception):
    pass


def encode_base64(bytes):
    return base64.encodebytes(bytes).strip().decode('ASCII')

def calculate_digest(filename):
    hash = sha256()
    with filename.open('rb') as input:
        while True:
            data = input.read(1024*1024)
            if not data:
                break
            hash.update(data)
    digest = hash.hexdigest()
    return f"sha256:{digest}"

def calculate_gziped_digest(filename):
    hash = sha256()
    with gzip.open(filename, 'rb') as input:
        while True:
            data = input.read(1024*1024)
            if not data:
                break
            hash.update(data)
    digest = hash.hexdigest()
    return f"sha256:{digest}"


DEFAULT_ALGS = {
    "EC": "ECDH-ES+A256KW",
    "RSA": "RSA-OAEP",
}

def encrypt(input_stream, encrypted_filename):
    backend = default_backend()
    symkey = os.urandom(32)
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(symkey), modes.CTR(nonce), backend=backend)
    encryptor = cipher.encryptor()
    hmac_hash = hmac.HMAC(symkey, hashes.SHA256(), backend=default_backend())
    sha_hash_encrypted = sha256()
    sha_hash_unencrypted = sha256()
    with input_stream, encrypted_filename.open('wb') as output:
        while True:
            data = input_stream.read(1024*1024)
            if not data:
                break
            sha_hash_unencrypted.update(data)
            data = encryptor.update(data)
            sha_hash_encrypted.update(data)
            hmac_hash.update(data)
            output.write(data)
        data = encryptor.finalize()
        sha_hash_encrypted.update(data)
        hmac_hash.update(data)
        output.write(data)
    hmac_hash = hmac_hash.finalize()
    sha_hash_encrypted = sha_hash_encrypted.hexdigest()
    sha_hash_unencrypted = sha_hash_unencrypted.hexdigest()
    pub_data = {
        "cipher": "AES_256_CTR_HMAC_SHA256",
        "hmac": encode_base64(hmac_hash),
        "cipheroptions": {}
    }
    payload = {
        "symkey": encode_base64(symkey),
        "digest": f"sha256:{sha_hash_unencrypted}",
        "cipheroptions": {"nonce": encode_base64(nonce)}
    }
    return pub_data, payload, sha_hash_encrypted

class Descriptor:
    def __init__(self, filename, media_type, digest, size, annotations=None):
        self.filename = filename
        self.media_type = media_type
        if digest is None:
            digest = calculate_digest(filename)
        self.digest = digest
        self._unpacked_digest = None
        self.data = None
        self.size = size
        self.annotations = annotations if annotations is not None else {}
        self.converted_media_type = None
        self.encryption_keys = []
        self.status = 'keep'

    @property
    def unpacked_digest(self):
        if self._unpacked_digest is None:
            if self.media_type == 'squashfs':
                self._unpacked_digest = self.digest
            elif self.media_type == 'tar':
                self._unpacked_digest = self.digest
            elif self.media_type == 'tar+gzip':
                self._unpacked_digest = calculate_gziped_digest(self.filename)
            elif self.media_type.endswith('+encrypted'):
                self._unpacked_digest = self.digest
            else:
                raise RuntimeError()
        return self._unpacked_digest

    def convert(self, media_type):
        if self.media_type != media_type:
            self.converted_media_type = media_type

    @classmethod
    def from_data(cls, data, media_type, annotations=None):
        hash = sha256(data).hexdigest()
        digest = f"sha256:{hash}"
        result = cls(None, media_type, digest, len(data), annotations)
        if media_type in ("tar+gzip", "tar+zstd"):
            raise NotImplemented()
        else:
            result._unpacked_digest = digest
        result.data = data
        return result

    def export(self, path):
        temporary_file = None
        if self.data:
            input_stream = io.BytesIO(self.data)
        else:
            input_stream = self.filename.open('rb')
        if self.converted_media_type is None:
            if not self.encryption_keys:
                output_filename = path / self.digest.split(':', 1)[1]
                with input_stream, output_filename.open('wb') as output:
                    shutil.copyfileobj(input_stream, output)
                return type(self)(output_filename, self.media_type, self.digest, self.size, self.annotations)
            media_type = self.media_type
        elif self.converted_media_type == "squashfs":
            print(f"Convert {self.media_type}")
            convert = IMAGE_CONVERTERS.get(self.media_type)
            if convert is None:
                raise NotImplemented()
            squash_filename = path / f"{self.digest}.sq"
            diff_digest = convert(input_stream, squash_filename)
            self._unpacked_digest = f"sha256:{diff_digest}"
            if not self.encryption_keys:
                digest = calculate_digest(squash_filename)
                output_filename = squash_filename.with_name(digest.split(':',1)[1])
                squash_filename.rename(output_filename)
                return type(self)(output_filename, self.converted_media_type, digest, output_filename.stat().st_size, self.annotations)
            else:
                temporary_file = squash_filename
                input_stream = squash_filename.open('rb')
                media_type = "squashfs"
        else:
            raise NotImplemented()

        assert self.encryption_keys
        print(f"Encrypt {media_type}")
        encrypted_filename = path / "enc"
        pub_data, payload, sha_hash_encrypted = encrypt(input_stream, encrypted_filename)

        jwetoken = jwe.JWE(json.dumps(payload).encode('utf-8'),
            protected={"enc": "A256GCM"},
        )
        for key in self.encryption_keys:
            jwetoken.add_recipient(key, header={"alg": DEFAULT_ALGS[key.key_type]})
        enc = jwetoken.serialize()
        annotations = dict(self.annotations, **{
            "org.opencontainers.image.enc.keys.jwe": base64url_encode(enc),
            "org.opencontainers.image.enc.pubopts": base64url_encode(json.dumps(pub_data)),
        })
        output_filename = path / sha_hash_encrypted
        encrypted_filename.rename(output_filename)
        if temporary_file is not None:
            temporary_file.unlink()
        result = type(self)(output_filename, media_type + "+encrypted",
            f"sha256:{sha_hash_encrypted}", output_filename.stat().st_size,
            annotations)
        result._unpacked_digest = result.digest
        return result

    def read(self):
        if self.data:
            return self.data
        return self.filename.read_bytes()


class ImageManifest:
    DIRECTORY_TRANSPORT = "Directory Transport Version: 1.1\n"
    MANIFEST_DOCKER_MEDIA_TYPE = "application/vnd.docker.distribution.manifest.v2+json"
    MANIFEST_OCI_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
    MEDIA_TYPES = {
        MANIFEST_OCI_MEDIA_TYPE: {
            "config": "application/vnd.oci.image.config.v1+json",
            "tar": "application/vnd.oci.image.layer.v1.tar",
            "tar+gzip": "application/vnd.oci.image.layer.v1.tar+gzip",
            "tar+zstd": "application/vnd.oci.image.layer.v1.tar+zstd",
            "tar+encrypted": "application/vnd.oci.image.layer.v1.tar+encrypted",
            "tar+gzip+encrypted": "application/vnd.oci.image.layer.v1.tar+gzip+encrypted",
            "tar+zstd+encrypted": "application/vnd.oci.image.layer.v1.tar+zstd+encrypted",
            "squashfs": "application/vnd.oci.image.layer.v1.squashfs",
            "squashfs+encrypted": "application/vnd.oci.image.layer.v1.squashfs+encrypted",
        },
        MANIFEST_DOCKER_MEDIA_TYPE: {
            "config": "application/vnd.docker.container.image.v1+json",
            "tar": "application/vnd.docker.image.rootfs.diff.tar",
            "tar+gzip": "application/vnd.docker.image.rootfs.diff.tar.gzip",
            "tar+zstd": "application/vnd.docker.image.rootfs.diff.tar.zstd",
            "tar+encrypted": "application/vnd.docker.image.rootfs.diff.tar+encrypted",
            "tar+gzip+encrypted": "application/vnd.docker.image.rootfs.diff.tar.gzip+encrypted",
            "tar+zstd+encrypted": "application/vnd.docker.image.rootfs.diff.tar.zstd+encrypted",
            "squashfs": "application/vnd.docker.image.rootfs.diff.squashfs",
            "squashfs+encrypted": "application/vnd.docker.image.rootfs.diff.squashfs+encrypted",
        }
    }
    _REVERSED_MEDIA_TYPES = {
        key: value for types in MEDIA_TYPES.values() for value, key in types.items()
    }

    def __init__(self, path, manifest_format=None):
        self.path = path
        self.schema_version = 2
        self.manifest_format = manifest_format if manifest_format is not None else self.MANIFEST_DOCKER_MEDIA_TYPE
        self.config = None
        self.layers = []
        self.annotations = {}

    @classmethod
    def _make_descriptor(cls, path, meta):
        media_type = meta['mediaType']
        media_type = cls._REVERSED_MEDIA_TYPES.get(media_type, media_type)
        digest = meta['digest']
        size = meta['size']
        annotations = meta.get('annotations', {})
        return Descriptor(path / digest.split(':', 1)[1], media_type, digest, size, annotations)

    @classmethod
    def from_path(cls, path):
        path = Path(path)
        if (path / "index.json").exists():
            with (path / "index.json").open('rb') as index:
                index = json.load(index)
            manifests = index.get('manifests', [])
            if len(manifests) != 1:
                raise RuntimeError("unsupported")
            manifest_file = Path(path, "blobs", *manifests[0]['digest'].split(':'))
            path = manifest_file.parent
        else:
            manifest_file = path / "manifest.json"
        with manifest_file.open('rb') as manifest:
            manifest = json.load(manifest)
        if manifest.get("schemaVersion") != 2:
            raise FormatError("unkown schema version")
        media_type = manifest.get("mediaType", cls.MANIFEST_OCI_MEDIA_TYPE)
        result = cls(path, media_type)
        result.config = cls._make_descriptor(path, manifest["config"])
        result.layers = [
            cls._make_descriptor(path, layer)
            for layer in manifest["layers"]
        ]
        result.annotations = manifest.get('annotations',{})
        return result

    def _descriptor_to_dict(self, manifest_format, descriptor):
        media_type = descriptor.media_type
        result = {
            "mediaType": self.MEDIA_TYPES[manifest_format].get(media_type, media_type),
            "size": descriptor.size,
            "digest": descriptor.digest,
        }
        if descriptor.annotations:
            result["annotations"] = descriptor.annotations
        return result

    def export(self, path, manifest_format=None):
        path = Path(path)
        path.mkdir()
        if manifest_format is None:
            manifest_format = self.manifest_format
        export_layers = []
        new_diffs = []
        digests = {}
        for layer in self.layers:
            digest = layer.unpacked_digest
            if layer.status == 'remove':
                new_digest = None
            else:
                exported = layer.export(path)
                new_digest = exported.unpacked_digest
                export_layers.append(exported)
                if layer.status == 'new':
                    new_diffs.append(new_digest)
            digests[digest] = new_digest
        config = json.loads(self.config.read())
        config['rootfs']['diff_ids'] = [
            digests[digest]
            for digest in config['rootfs']['diff_ids']
            if digests[digest] is not None
        ] + new_diffs
        config = Descriptor.from_data(json.dumps(config).encode('utf8'), "config")
        manifest = {
            "schemaVersion":2,
        }
        if manifest_format != self.MANIFEST_OCI_MEDIA_TYPE:
            manifest["mediaType"] = manifest_format
        manifest['config'] = self._descriptor_to_dict(manifest_format, config.export(path))
        manifest['layers'] = [
            self._descriptor_to_dict(manifest_format, layer)
            for layer in export_layers
            
        ]
        with (path / "manifest.json").open("w", encoding="utf8") as output:
            json.dump(manifest, output)
        with (path / "version").open("w", encoding="utf8") as output:
            output.write(self.DIRECTORY_TRANSPORT)

    def publish(self, docker_url, manifest_format=None):
        from .store import Store
        from notary import generate_hashes
        if manifest_format is None:
            manifest_format = self.manifest_format
        manifest = {
            "schemaVersion":2,
        }
        if manifest_format != self.MANIFEST_OCI_MEDIA_TYPE:
            manifest["mediaType"] = manifest_format
        manifest['config'] = self._descriptor_to_dict(manifest_format, self.config)
        manifest['layers'] = [
            self._descriptor_to_dict(manifest_format, layer)
            for layer in self.layers
        ]
        
        store = Store(docker_url)
        hub = store._hub
        for layer in self.layers:
            if hub.has_blob(layer.digest):
                print(f"Blob {layer.digest} found.")
            else:
                print(f"Blob {layer.digest} uploading...")
                hub.post_blob(str(layer.filename))
                print("finished.")
        if hub.has_blob(self.config.digest):
            print(f"Config {self.config.digest} found.")
        else:
            print(f"Config {self.config.digest} uploading...")
            hub.post_blob(str(self.config.filename))
            print("finished.")
        print("Writing manifest to image destination.")
        data = json.dumps(manifest).encode()
        hub.post_manifest(data)
        sha256_digest = sha256(data).hexdigest()
        sha512_digest = sha512(data).hexdigest()
        print(f"{len(data)} --sha256 {sha256_digest} --sha512 {sha512_digest}")
        notary = store._notary
        if notary is not None:
            hashes = generate_hashes(data)
            notary.add_target(store.url.tag, hashes)
            notary.publish()
