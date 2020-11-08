import sys
import os
from concil.dockerhub import parse_docker_url
from concil.store import unsplit_url, Store
from concil.run import Config, run

class StoreConfig(Config):
    def __init__(self, store, private_key=None):
        self.store = store
        self.private_key = private_key
        self.manifest = store.get_manifest()
        self.image_config = store.get_config(self.manifest['config'])
        self.config = self.image_config.get('config', {})

    def get_layers(self):
        layers = {}
        for layer in self.manifest["layers"]:
            filepath = self.store.get_layer(layer)
            filename = str(filepath)
            if layer["mediaType"].endswith("+encrypted"):
                filename += ',' + self.get_key(layer)
            layers[filepath.name] = filename
        return [layers[diff_id] for diff_id in self.image_config['rootfs']['diff_ids']]


def main():
    if len(sys.argv) <= 1:
        print("Usage: concil_run.py <docker_url|filename> [-p private_key.pem] [-v volume] args")
        return
    
    filename = sys.argv[1]
    volumes = []
    args = sys.argv[2:]
    if args and args[0] == '-p':
        private_key = args[1]
        args = args[2:]
    else:
        private_key = None
    while args and args[0] == '-v':
        volumes.append(args[1])
        args = args[2:]
    if args and args[0] == '--':
        args = args[1:]

    if filename.startswith('docker://'):
        parts = parse_docker_url(filename)
        username = parts.username or os.environ.get('CONCIL_STORE_USER')
        password = parts.username or os.environ.get('CONCIL_STORE_PASSWORD')
        full_url = unsplit_url(parts.scheme, parts.hostname, parts.port, parts.path, username, password)
        store = Store(full_url)
        config = StoreConfig(store, private_key)
    else:
        config = Config(filename, private_key)
    run(config, args, volumes)

if __name__ == '__main__':
    main()
