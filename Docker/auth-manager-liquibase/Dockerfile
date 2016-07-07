FROM maven:3.3.9-jdk-8

MAINTAINER Ivan Suftin <isuftin@usgs.gov>

VOLUME /root/artifacts

WORKDIR /root/artifacts

RUN mkdir -p /root/artifacts

RUN mkdir -p /root/liquibase

ENV LIQUIBASE_HOME /root/liquibase

ADD https://github.com/liquibase/liquibase/releases/download/liquibase-parent-3.4.2/liquibase-3.4.2-bin.tar.gz $LIQUIBASE_HOME/

WORKDIR /root/liquibase

RUN tar xvf liquibase-3.4.2-bin.tar.gz