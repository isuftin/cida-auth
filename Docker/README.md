## Docker Instructions

This application is set up to use Docker and Docker Compose to create a local development environment. Running `docker-compose up` should be all that is needed .

### Environments

The file compose.env is a [Docker Compose environment file](https://docs.docker.com/compose/compose-file/#env-file) and includes the variable values that some of the service require. For local development, feel free to alter this file to your liking. However, if you wish to leave this file be and create a secondary environemnt file, I suggest creating `compose_local.env` because that's already included in .gitignore. In order to use your local file, you should export an environment variable named `AUTH_ENV_LOCAL`:

```
$ export AUTH_ENV_LOCAL=".local"
```

This will cause Docker Compose to pick up your `compose_local.env` file and use the values in there to drive the services.  These values typically include passwords, internal URLs, etc. If any changes are made to any ldif files or to the `addAll.sh` file, you will need to rebuild the auth-ldap container.

### OpenLDAP

The Docker Compose template includes an OpenLDAP server as well as a container that fills the server with users. Check https://github.com/osixia/docker-openldap for more information. If you do not need OpenLDAP support or plan on using your own LDAP server, either comment out the sections for OpenLDAP in docker-compose.yml (ldap-server and ldap-seed) or run compose without those two containers.

TODO- Implement LDAPS. Currently, only insecure LDAP is working. I've not yet attempted to set up secure LDAPS

#### LDAP Users

The users are currently stored in the `auth-ldap/ldif_files/people.ldif` file. Feel free to change the user names/passwords to fit your testing.  The password for each user is 'test'. Feel free to change that as well by hashing a text value using SHA1 and entering into the people.ldif file.

The username for the LDAP admin user is `admin`. The password for the LDAP admin user is `admin`. The password is set in the environments file you run your docker-compose against. The key for the value is `LDAP_ADMIN_PASSWORD`. 

#### LDAP Groups

You may or may not need groups for your LDAP testing, but the seed container will create a single group anyway and put all the users that are in people.ldif by default into that group. The group name is `cida_auth_group`. Feel free to change this if you need. The seed container also modifies the LDAP configuration using the `auth-ldap/ldif_files/addUsersToGroup.ldif` file. If you do modify user names, you should update the `addUsersToGroup.ldif` files to match. If you choose not to use groups, you can comment out the line in `addAll.sh` that begins with `ldapmodify`.
