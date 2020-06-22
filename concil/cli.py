import argparse
from .image import ImageManifest
from cryptography.hazmat.backends import default_backend
from jwcrypto import jwk

def main():
    parser = argparse.ArgumentParser(description='Convert container images.')
    parser.add_argument('source-image', help='source directory')
    parser.add_argument('destination-image', help='destination directory')
    parser.add_argument('--squashfs', action='store_true',
        help='convert layers to squashfs')
    parser.add_argument('--encryption', metavar="key", nargs="+",
        help='encryption keys')
    args = parser.parse_args()
    print(args)
    keys = []
    for key in args.encryption:
        with open(key, 'rb') as inp:
            keys.append(jwk.JWK.from_pem(inp.read()))
    print(keys)
    image = ImageManifest.from_path(getattr(args,'source-image'))
    if args.squashfs:
        for layer in image.layers:
            layer.convert("squashfs")
    for layer in image.layers:
        layer.encryption_keys = keys
    image.export(getattr(args, 'destination-image'), image.MANIFEST_DOCKER_MEDIA_TYPE)

if __name__ == "__main__":
    main()