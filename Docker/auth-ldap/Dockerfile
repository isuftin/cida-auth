FROM osixia/openldap:1.1.3

MAINTAINER Ivan Suftin <isuftin@usgs.gov>

RUN mkdir /ldif_files

COPY ldif_files /ldif_files

# Because this container needs to wait for LDAP to be up, install Dockerize
# and control this container running its command based on the LDAP server being up
#
# https://github.com/jwilder/dockerize
# https://github.com/mefellows/dockerize-compose-demo

ENV DOCKERIZE_VERSION "0.2.0"

RUN apt-get update && apt-get install -y wget

RUN wget https://github.com/jwilder/dockerize/releases/download/v${DOCKERIZE_VERSION}/dockerize-linux-amd64-v${DOCKERIZE_VERSION}.tar.gz

RUN tar -C /usr/local/bin -xzvf dockerize-linux-amd64-v${DOCKERIZE_VERSION}.tar.gz
