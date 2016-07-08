## Docker Instructions

This application is set up to use Docker and Docker Compose to create a local development environment. Running `docker-compose up` should be all that is needed .

### Environments

The file compose.env is a [Docker Compose environment file](https://docs.docker.com/compose/compose-file/#env-file) and includes the variable values that some of the service require. For local development, feel free to alter this file to your liking. However, if you wish to leave this file be and create a secondary environemnt file, I suggest creating `compose_local.env` because that's already included in .gitignore. In order to use your local file, you should export an environment variable named `AUTH_ENV_LOCAL`:

```
$ export AUTH_ENV_LOCAL="_local"
```

This will cause Docker Compose to pick up your `compose_local.env` file and use the values in there to drive the services.  These values typically include passwords, internal URLs, etc.

