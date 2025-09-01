<p align="center">
  <img style="max-width: 100%;width: 300px;" src="https://raw.githubusercontent.com/ruema/concil/master/docs/concil.svg" alt="concil logo"/>
</p>

# concil

**concil** is a simple, rootless, and daemonless container manager designed to run OCI-compliant Linux containers.
It provides a lightweight and secure way to run standalone applications in isolated user-space environments.
With a focus on simplicity and security, `concil` offers features like image encryption and signature verification, making it an excellent alternative to more complex containerization tools.

## Features

*   **OCI-Compliant:** Run containers from OCI-compliant registries like Docker Hub.
*   **Rootless and Daemonless:** Run containers without requiring root privileges or a background daemon.
*   **Image Encryption:** Encrypt container layers for enhanced security.
*   **Signature Verification:** Verify the integrity and authenticity of container images using cosign.
*   **Image Management:** Build, copy, and manage container images with a simple command-line interface.
*   **Low Complexity:** A straightforward and easy-to-understand tool for container management.

## Comparison with Docker

|                      | Docker | Concil |
|----------------------|:------:|:------:|
| OCI-Repository       | ✓      | ✓      |
| Signature            | ✓      | ✓      |
| Encryption           | ✗      | ✓      |
| Rootless / Daemonless| ✗      | ✓      |
| Network isolation    | ✓      | ✗      |
| Complexity           | high   | low    |

## Installation

You need Python 3.6+ to run concil.
It uses image layers in squashfs-format. Build the squashfuse-library from https://github.com/ruema/squashfuse.
To create squashfs-layers `tar2sq` from [squashfs-tools-ng](https://github.com/AgentD/squashfs-tools-ng) is used.
As a third component [fuse-overlayfs](https://github.com/containers/fuse-overlayfs) is used to for interactive layer creation.

## Quickstart

### Running a container

```shell
$ concil_run.py docker://docker.io/library/alpine:latest
```

### Creating a container

First download a base image to a local directory:
```shell
$ concil copy docker://docker.io/library/alpine:latest ./alpine
```

Then add a directory as additional layer:
```shell
$ mkdir -p ./layer/bin
$ echo "echo 'Hello world!'" >./layer/bin/hello.sh
$ chmod a+x ./layer/bin/hello.sh
$ concil copy --add-layer ./layer --entry-point /bin/hello.sh ./alpine ./hello_world
```

The container is finished and can be run:
```shell
$ concil_run.py ./hello_world
```

