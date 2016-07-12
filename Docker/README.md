## Docker Instructions

This application is set up to use Docker and Docker Compose to create a local development environment. Running `docker-compose up` should be all that is needed .

### Environments

The file compose.env is a [Docker Compose environment file](https://docs.docker.com/compose/compose-file/#env-file) and includes the variable values that some of the service require. For local development, feel free to alter this file to your liking. However, if you wish to leave this file be and create a secondary environemnt file, I suggest creating `compose_local.env` because that's already included in .gitignore. In order to use your local file, you should export an environment variable named `AUTH_ENV_LOCAL`:

```
$ export AUTH_ENV_LOCAL=".local"
```

This will cause Docker Compose to pick up your `compose_local.env` file and use the values in there to drive the services.  These values typically include passwords, internal URLs, etc.

### OpenLDAP

The Docker Compose template includes an OpenLDAP server as well as a container that fills the server with a user. One issue you may run into is when you first run the seeding server, it will complain about permissions. This may be an issue with your host file system. To get around this, change the permissions for the `/auth-ldap` folder to 777 by issuing the following: `chmod -R 777 ./auth-ldap` from the directory that the docker-compose file is in.

The user that's created by default when the LDAP server begins is named `test_user`. You can find more information about this user by reading the file `./auth-ldap/ldif_files/people.ldif`. The password for this user is `test`.

If you do not need OpenLDAP support or plan on using your own LDAP server, either comment out the sections for OpenLDAP in docker-compose.yml (ldap-server and ldap-seed) or run compose without those two containers: `docker-compose up auth-database auth-manager-console auth-manager-core`


