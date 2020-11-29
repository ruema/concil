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

