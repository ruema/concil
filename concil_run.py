#!/usr/bin/env python
import sys
import os
from concil.dockerhub import parse_docker_url
from concil.store import unsplit_url, Store
from concil.run import Config, run

class StoreConfig(Config):
    def __init__(self, store):
        self.store = store
        self.manifest = store.get_manifest()
        self.image_config = store.get_config(self.manifest['config'])
        self.config = self.image_config.get('config', {})

    def get_layers(self):
        layers = [self.store.get_layer(l) for l in self.manifest['layers']]
        diff_ids = {l.name: str(l) for l in layers}
        return [diff_ids[diff_id] for diff_id in self.image_config['rootfs']['diff_ids']]


def main():
    if len(sys.argv) <= 1:
        print("Usage: concil_run.py <docker_url> [-v volume] args")
        return
    
    docker_url = sys.argv[1]
    volumes = []
    args = sys.argv[2:]
    while args and args[0] == '-v':
        volumes.append(args[1])
        args = args[2:]
    if args and args[0] == '--':
        args = args[1:]
        
    parts = parse_docker_url(docker_url)
    username = parts.username or os.environ.get('CONCIL_USER')
    password = parts.username or os.environ.get('CONCIL_PASSWORD')
    full_url = unsplit_url(parts.scheme, parts.hostname, parts.port, parts.path, username, password)
    store = Store(full_url)
    config = StoreConfig(store)
    run(config, args, volumes)

if __name__ == '__main__':
    main()
