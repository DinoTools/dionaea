# Quick reference

- **Maintained by**:
  [dionaea Community](https://github.com/DinoTools/dionaea/)

- **Where to get help**:
  [dionaea GitHub issues](https://github.com/DinoTools/dionaea/issues)

# Tags

- nightly - Build every night from the default branch
- edge - Build when pushed to default branch
- x.y.z - Specific version (Example: 0.9.2)
- latest - The latest specific version

# What is dionaea?

dionaea is a low interaction honeypot.
The code from the [official dionaea repository](https://github.com/DinoTools/dionaea) is used to build the service during the image build process.

# How to use this image.

## Start a dionaea instance

```console
$ docker run --rm -it -p 21:21 -p 42:42 -p 69:69/udp -p 80:80 -p 135:135 -p 443:443 -p 445:445 -p 1433:1433 -p 1723:1723 -p 1883:1883 -p 1900:1900/udp -p 3306:3306 -p 5060:5060 -p 5060:5060/udp -p 5061:5061 -p 11211:11211 dinotools/dionaea
```

## ... via [docker-compose](https://github.com/docker/compose)

Example ```docker-compose.yml```

```yaml
version: '3.8'

services:
  dionaea:
    image: dinotools/dionaea
    restart: always
```

# How to extend this image

There are many ways to extend the image, but here are some we found useful.

## Entrypoint

In the image a custom script is used as entrypoint. This helps to ensure all required data, log and config directories and files are in place.

If the following base directories are missing the default files from the build process are copied.

- config dir: /opt/dionaea/etc/dionaea
- data dir: /opt/dionaea/var/lib/dionaea
- log dir: /opt/dionaea/var/log/dionaea

## Environment variables

### `DIONAEA_SKIP_INIT`

The default directories and files **are not copied** even if the base directory is missing

### `DIONAEA_FORCE_INIT`

The default directories and files **are copied** even if the base directory exists. But only missing directories and files should be created.

### `DIONAEA_FORCE_INIT_CONF`

Same as `DIONAEA_FORCE_INIT` but the action is forced only for the config directory.

### `DIONAEA_FORCE_INIT_DATA`

Same as `DIONAEA_FORCE_INIT` but the action is forced only for the data and log directories.

## Persistent storage

It is recommended to use a persistent storage like docker volumes or bind mounts for the following directories.

- /opt/dionaea/etc
- /opt/dionaea/var/lib
- /opt/dionaea/var/log

## Build a custom image

### Create a `Dockerfile` in your project

```dockerfile
FROM dinotools/dionaea:latest
COPY conf/your-service.yaml /opt/dionaea/etc/dionaea/services-enabled/
COPY conf/your-ihandler.yaml /opt/dionaea/etc/dionaea/ihandlers-enabled/
```

Then, run the command to build the image:

```console
docker build -t my-dionaea
```

# User Feedback

## Issues

If you have any problems with or questions about this image, please create an [GitHub issue](https://github.com/DinoTools/dionaea/issues).

## Contributing

You are invited to contribute new features, fixes or updates.
We recommend discussing your ideas through a [GitHub issue](https://github.com/DinoTools/dionaea/issues), before you start.
