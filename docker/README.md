# What is dionaea?

dionaea is a low interaction honeypot.
The code from the [official dionaea repository](https://github.com/DinoTools/dionaea) is used to build the service during the image build process.

# How to use this image.

## Build a custom image

### Create a `Dockerfile` in your project

```dockerfile
FROM dionae:0.9
COPY conf/your-service.yaml /opt/dionaea/etc/dionaea/services-enabled/
COPY conf/your-ihandler.yaml /opt/dionaea/etc/dionaea/ihandlers-enabled/
```

Then, run the commands to build and run the Docker image:

```console
docker build -t my-dionaea
docker run --rm -it -p 21:21 -p 42:42 -p 69:69/udp -p 80:80 -p 135:135 -p 443:443 -p 445:445 -p 1433:1433 -p 1723:1723 -p 1883:1883 -p 1900:1900/udp -p 3306:3306 -p 5060:5060 -p 5060:5060/udp -p 5061:5061 -p 11211:11211 my-dionaea
```

### Configuration

If you don't want to include a `Dockerfile` in your project, it is sufficient to do the following:

```console
$ docker run -it --rm -v "$PWD/etc":/opt/dionaea/etc/dionaea -p 21:21 -p 42:42 -p 69:69/udp -p 80:80 -p 135:135 -p 443:443 -p 445:445 -p 1433:1433 -p 1723:1723 -p 1883:1883 -p 1900:1900/udp -p 3306:3306 -p 5060:5060 -p 5060:5060/udp -p 5061:5061 -p 11211:11211 dinotools/dionaea
```

# User Feedback

## Issues

If you have any problems with or questions about this image, please create an [GitHub issue](https://github.com/DinoTools/dionaea/issues).

## Contributing

You are invited to contribute new features, fixes or updates.
We recommend discussing your ideas through a [GitHub issue](https://github.com/DinoTools/dionaea/issues), before you start.
