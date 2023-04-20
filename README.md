<p align="center">
  <img style="max-width: 100%;width: 300px;" src="https://raw.githubusercontent.com/ruema/concil/master/docs/concil.svg" alt="concil logo"/>
</p>


# concil

concil is a simple container manager to run OCI-conform linux containers.

It's aim is to run standalone applications in isolated environments in user space.

Short comparision with Docker:

|                      | Docker | Concil |
|----------------------|:------:|:------:|
|OCI-Repository        | ✓      | ✓      |
|Signature             | ✓      | ✓      |
|Encryption            | ✗      | ✓      |
|Rootless / Daemonless | ✗      | ✓      |
|Network isolation     | ✓      | ✗      |
|Complexity            | high   | low    |

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

