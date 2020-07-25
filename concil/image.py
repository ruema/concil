import os
import json
import tempfile
import base64
import gzip
import subprocess
import shutil
import io
from hashlib import sha256
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from jwcrypto import jwk, jwe

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

def convert_tar_to_squash(path, input):
    tmpdir = tempfile.mkdtemp(dir=path)
    output_filename = tmpdir + '.sq'
    process = subprocess.Popen(["tar", "-x"], stdin=subprocess.PIPE, cwd=tmpdir)
    hash = sha256()
    while True:
        data = input.read(1024*1024)
        if not data:
            break
        process.stdin.write(data)
        hash.update(data)
    process.stdin.close()
    process.wait()
    unpacked_digest = hash.hexdigest()
    subprocess.run(["mksquashfs", tmpdir, output_filename, "-all-root", "-no-progress"])
    shutil.rmtree(tmpdir)
    return Path(output_filename), f"sha256:{unpacked_digest}"


class Descriptor:
    def __init__(self, filename, media_type, digest, size, annotations=None):
        self.filename = filename
        self.media_type = media_type
        self.digest = digest
        self.unpacked_digest = None
        self.previous_digest = None
        self.data = None
        self.size = size
        self.annotations = annotations
        self.converted_media_type = None
        self.encryption_keys = []

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
            result.unpacked_digest = digest
        result.data = data
        return result

    def export(self, path):
        if self.data:
            input_stream = io.BytesIO(self.data)
        else:
            input_stream = self.filename.open('rb')
        if self.converted_media_type is None:
            pass
        elif self.converted_media_type == "squashfs":
            if self.media_type in ('tar', 'tar+gzip'):
                open_ = gzip.open if self.media_type == 'tar+gzip' else lambda f:f
                with open_(self.filename.open('rb')) as input:
                    squash_filename, previous_digest = convert_tar_to_squash(path, input)
                if not self.encryption_keys:
                    digest = calculate_digest(squash_filename)
                    output_filename = squash_filename.with_name(digest.split(':',1)[1])
                    squash_filename.rename(output_filename)
                    result = type(self)(output_filename, self.converted_media_type, digest, output_filename.stat().st_size, self.annotations)
                    result.unpacked_digest = digest
                    result.previous_digest = previous_digest
                    return result
                else:
                    input_stream = squash_filename.open('rb')
            else:
                raise NotImplemented()
        else:
            raise NotImplemented()

        if self.encryption_keys:
            backend = default_backend()
            symkey = os.urandom(32)
            nonce = os.urandom(16)
            cipher = Cipher(algorithms.AES(symkey), modes.CTR(nonce), backend=backend)
            encryptor = cipher.encryptor()
            hmac_hash = hmac.HMAC(symkey, hashes.SHA256(), backend=default_backend())
            sha_hash_encrypted = sha256()
            sha_hash_unencrypted = sha256()
            encrypted_filename = path / "enc"
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
            protected_header = {"alg": "RSA-OAEP", "enc": "A256GCM"}
            jwetoken = jwe.JWE(json.dumps(payload).encode('utf-8'),
                protected=protected_header
            )
            for key in self.encryption_keys:
                jwetoken.add_recipient(key)
            enc = jwetoken.serialize()
            annotations = dict(self.annotations)
            annotations["org.opencontainers.image.enc.keys.jwe"] = encode_base64(enc.encode('utf8'))
            annotations["org.opencontainers.image.enc.pubopts"] = encode_base64(json.dumps(pub_data).encode('utf8'))
            output_filename = path / sha_hash_encrypted
            encrypted_filename.rename(output_filename)
            result = type(self)(output_filename, self.media_type + "+encrypted",
                f"sha256:{sha_hash_encrypted}", output_filename.stat().st_size,
                annotations)
            result.previous_digest = previous_digest
            result.unpacked_digest = result.digest
            return result
        else:
            output_filename = path / self.digest.split(':', 1)[1]
            with input_stream, output_filename.open('wb') as output:
                shutil.copyfileobj(input_stream, output)
            return type(self)(output_filename, self.media_type, self.digest, self.size, self.annotations)

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
        with (path / "manifest.json").open('rb') as manifest:
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
        layers = [layer.export(path) for layer in self.layers]
        if any(layer.unpacked_digest for layer in layers):
            # some layer-digest changed, need new config
            digests = {
                layer.previous_digest: layer.unpacked_digest
                for layer in layers
            }
            config = json.loads(self.config.read())
            config['rootfs']['diff_ids'] = [
                digests.get(digest, digest)
                for digest in config['rootfs']['diff_ids']
            ]
            config = Descriptor.from_data(json.dumps(config).encode('utf8'), "config")
        else:
            config = self.config
        manifest = {
            "schemaVersion":2,
        }
        if manifest_format != self.MANIFEST_OCI_MEDIA_TYPE:
            manifest["mediaType"] = manifest_format
        manifest['config'] = self._descriptor_to_dict(manifest_format, config.export(path))
        manifest['layers'] = [
            self._descriptor_to_dict(manifest_format, layer)
            for layer in layers
            
        ]
        with (path / "manifest.json").open("w", encoding="utf8") as output:
            json.dump(manifest, output)
        with (path / "version").open("w", encoding="utf8") as output:
            output.write(self.DIRECTORY_TRANSPORT)

