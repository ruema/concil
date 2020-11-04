import argparse
from pathlib import Path
from .image import ImageManifest, Descriptor
from . import store
from cryptography.hazmat.backends import default_backend
from jwcrypto import jwk


def generate_key(outputfilename, password):
    key = jwk.JWK.generate(kty='EC', crv='P-521')    
    with open(outputfilename + '.private.pem', 'wb') as output:
        output.write(key.export_to_pem(True, password.encode()))
    with open(outputfilename + '.pem', 'wb') as output:
        output.write(key.export_to_pem())


def main():
    store.TAR2SQFS = ["tar2sqfs", "-c", "zstd", "-X", "level=19"]
    parser = argparse.ArgumentParser(description='Convert container images.')
    parser.add_argument('source-image', help='source directory')
    parser.add_argument('destination-image', help='destination directory')
    parser.add_argument('--squashfs', action='store_true',
        help='convert layers to squashfs')
    parser.add_argument('--encryption', metavar="key", nargs="+",
        help='encryption keys')
    parser.add_argument('--list-layers', action='store_true', help='List layers')
    parser.add_argument('--remove-layer', metavar="layer", nargs="+",
        help='ID of layers to remove')
    parser.add_argument('--add-layer', metavar="layer", nargs="+",
        help='filename of new layers appended')
    args = parser.parse_args()
    keys = []
    for key in args.encryption or []:
        with open(key, 'rb') as inp:
            keys.append(jwk.JWK.from_pem(inp.read()))
    image = ImageManifest.from_path(getattr(args,'source-image'))
    if args.list_layers:
        print(f"{'Digest':65s} {'Size':12s} Media-Type")
        for layer in image.layers:
            print(f"{layer.digest.split(':',1)[1]:65s} {layer.size:12d} {layer.media_type}")
        return
    if args.remove_layer:
        to_be_removed = tuple(args.remove_layer)
        print(f"{'Digest':65s} {'Size':12s} Media-Type")
        for layer in image.layers:
            digest = layer.digest.split(':',1)[1]
            if digest.startswith(to_be_removed):
                print(f"{layer.digest.split(':',1)[1]:65s} {layer.size:12d} {layer.media_type} removed.")
                layer.status = 'remove'
            else:
                print(f"{layer.digest.split(':',1)[1]:65s} {layer.size:12d} {layer.media_type} kept.")
    if args.add_layer:
        for filename in args.add_layer:
            path = Path(filename)
            if path.suffix == '.sq':
                media_type = 'squashfs'
            elif path.suffix == '.tar':
                media_type = 'tar'
            elif path.suffix in ('.gz', '.tgz'):
                media_type = 'tar+gz'
            else:
                raise RuntimeError("unsupported file type")
            layer = Descriptor(path, media_type, None, path.stat().st_size)
            layer.status = 'new'
            print(f"{layer.digest.split(':',1)[1]:65s} {layer.size:12d} {layer.media_type} added.")
            image.layers.append(layer)
    if args.squashfs:
        for layer in image.layers:
            layer.convert("squashfs")
    for layer in image.layers:
        layer.encryption_keys = keys
    image.export(getattr(args, 'destination-image'), image.MANIFEST_DOCKER_MEDIA_TYPE)

if __name__ == "__main__":
    main()
