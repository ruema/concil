import base64
import hashlib
import json
import datetime
from pathlib import Path
from ecdsa import SigningKey, VerifyingKey
from ecdsa.util import sigencode_der, sigdecode_der
import logging
logger = logging.getLogger(__file__)

class Cosign:
    def __init__(self, hub, config={}):
        self._hub = hub
        self._config = config

    def publish(self, hashsum256, private_key):
        with open(private_key) as f:
           sk = SigningKey.from_pem(f.read())
        utcnow = datetime.datetime.utcnow().isoformat() + 'Z'
        simplesigning = {
            "critical": {
                "identity": {"docker-reference": self._hub.repository},
                "image": {"docker-manifest-digest": "sha256:%s" % hashsum256},
                "type": "cosign container image signature"
            },
            "optional": None
        }
        simplesigning_blob = json.dumps(simplesigning).encode('utf8')
        simplesigning_digest = hashlib.sha256(simplesigning_blob).hexdigest()
        new_signature = sk.sign_deterministic(simplesigning_blob, hashlib.sha256, sigencode=sigencode_der)
        new_signature = base64.standard_b64encode(new_signature).decode('ASCII')
        config = {
            "architecture":"",
            "created": utcnow,
            "history": [{"created":"0001-01-01T00:00:00Z"}],
            "os":"",
            "rootfs": {"type": "layers", "diff_ids": ["sha256:%s" % simplesigning_digest]},
            "config": {}
        }
        config_blob = json.dumps(config).encode('utf8')
        config_digest = hashlib.sha256(config_blob).hexdigest()
        manifest = {
            'schemaVersion': 2,
            'mediaType': 'application/vnd.oci.image.manifest.v1+json',
            'config': {
                'mediaType': 'application/vnd.oci.image.config.v1+json',
                'size': len(config_blob),
                'digest': 'sha256:%s' % config_digest
            },
            'layers': [{
                'mediaType': 'application/vnd.dev.cosign.simplesigning.v1+json',
                'size': len(simplesigning_blob),
                'digest': 'sha256:%s' % simplesigning_digest,
                'annotations': {'dev.cosignproject.cosign/signature': new_signature}
            }],
        }
        hub = self._hub
        if hub.has_blob("sha256:" + simplesigning_digest):
            print(f"Blob {simplesigning_digest} found.")
        else:
            print(f"Blob {simplesigning_digest} uploading...")
            hub.post_blob_data(simplesigning_blob, simplesigning_digest)
            print("finished.")

        if hub.has_blob("sha256:" + config_digest):
            print(f"Blob {config_digest} found.")
        else:
            print(f"Blob {config_digest} uploading...")
            hub.post_blob_data(config_blob, config_digest)
            print("finished.")

        print("Writing manifest to image destination.")
        data = json.dumps(manifest).encode()
        try:
            hub.post_manifest(data, tag='sha256-%s.sig' % hashsum256, content_type='application/vnd.oci.image.manifest.v1+json')
        except Exception as e:
            print(e.response.headers)
            print(e.response.content)
            raise

    def check_signature(self, manifest):
        hashsum256 = 'sha256-%s.sig' % hashlib.sha256(manifest).hexdigest()
        manifest = self._hub.get_manifest(hash=hashsum256, accept="application/vnd.docker.distribution.manifest.v1+json,application/vnd.docker.distribution.manifest.v1+prettyjws,application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.index.v1+json")
        manifest = json.loads(manifest)
        digest = manifest['layers'][-1]['digest']
        signature = manifest['layers'][-1]['annotations']['dev.cosignproject.cosign/signature']
        signature = base64.standard_b64decode(signature)
        blob = self._hub.open_blob(digest).content
        directory = self._config.get('key_dir', '.')
        if Path(directory).is_dir():
            for keyfile in Path(directory).glob("*.pub"):
                try:
                    logger.info('trying key %s', keyfile)
                    vk = VerifyingKey.from_pem(keyfile.read_bytes())
                    if vk.verify(signature, blob, hashlib.sha256, sigdecode=sigdecode_der):
                        return
                except Exception as e:
                    logger.debug(str(e))
        else:
            raise ValueError("no signing key found")
        raise ValueError("signature verify failed")
