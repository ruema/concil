#!/usr/bin/env python3
import logging
import os
import platform
import sys

from .dockerhub import parse_docker_url
from .oci_spec import current_architecture
from .run import AbstractConfig, LocalConfig, run
from .store import Store, unsplit_url


class StoreConfig(AbstractConfig):
    def __init__(self, store, private_key=None, environment=None):
        super().__init__(private_key, environment)
        self.store = store
        self.manifest = store.get_manifest(
            current_architecture(), platform.system().lower()
        )
        self.image_config = store.get_config(self.manifest["config"])
        self.config = self.image_config.get("config", {})

    def get_layers(self):
        layers = {}
        for layer in self.manifest["layers"]:
            filepath = self.store.get_layer(layer)
            filename = str(filepath)
            if layer["mediaType"].endswith("+encrypted"):
                filename += "," + self.get_key(layer)
            layers[filepath.name] = filename
        # now is a good time to cleanup the cache
        self.store.cache_cleanup()
        return [layers[diff_id] for diff_id in self.image_config["rootfs"]["diff_ids"]]


def main():
    if len(sys.argv) <= 1:
        print(
            "Usage: concil_run.py <docker_url|filename> [-p private_key.pem] [-v volume] args"
        )
        return
    args = sys.argv[1:]
    if args[0] == "--debug":
        logging.basicConfig(level=logging.DEBUG)
        args = args[1:]
    else:
        logging.basicConfig(level=logging.WARNING)

    filename = args[0]
    if filename.startswith("docker://"):
        parts = parse_docker_url(filename)
        if "@" in parts.netloc:
            full_url = filename
        else:
            username = os.environ.get("CONCIL_STORE_USER")
            password = os.environ.get("CONCIL_STORE_PASSWORD")
            if username:
                full_url = unsplit_url(
                    parts.scheme, parts.netloc, parts.path, username, password
                )
            else:
                full_url = filename
        store = Store(full_url)
        config = StoreConfig(store)
    else:
        config = LocalConfig(filename)
    config.parse_args(args[1:])
    sys.exit(run(config))


if __name__ == "__main__":
    main()
