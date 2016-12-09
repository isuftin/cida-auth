
1.1.8
-----
- Updated versions for plugins, H2, Postgresql driver, maven-compiler-plugin, build-helper-maven-plugin
- Updated Postgres and Oracle Liquibase profiles so both can be run against local or remote database
- Updated Postgres and Oracle Liquibase profile names so neither are specific to local or dev/qa/prod tiers
- Tested using OracleXE Docker https://hub.docker.com/r/wnameless/oracle-xe-11g/
- Tested using Portgres Docker https://hub.docker.com/_/postgres/
- Moved Docker configuration to https://github.com/USGS-CIDA/docker-cida-auth
- Created DockerHub container registry at:
	- https://hub.docker.com/r/usgs/auth-database/
	- https://hub.docker.com/r/usgs/auth-manager-console/
	- https://hub.docker.com/r/usgs/auth-manager-core/
	- https://hub.docker.com/r/usgs/auth-ldap-seed/