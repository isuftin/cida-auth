FROM postgres:9.5.3

MAINTAINER Ivan Suftin <isuftin@usgs.gov>

RUN echo "deb http://ppa.launchpad.net/webupd8team/java/ubuntu trusty main" > /etc/apt/sources.list.d/webupd8team-java.list && \	
	echo "deb-src http://ppa.launchpad.net/webupd8team/java/ubuntu trusty main" >> /etc/apt/sources.list.d/webupd8team-java.list && \
	apt-key adv --keyserver keyserver.ubuntu.com --recv-keys EEA14886 && \
	echo debconf shared/accepted-oracle-license-v1-1 select true | debconf-set-selections && \
	echo debconf shared/accepted-oracle-license-v1-1 seen true | debconf-set-selections && \
	apt-get update && \
	apt-get -y install oracle-java8-installer wget maven && \
	apt-get clean

ENV POSTGRES_PASSWORD postgres

ENV POSTGRES_USER postgres

ENV POSTGRES_DB cida_auth

ENV AUTH_VERSION ${AUTH_VERSION:-"1.2.6"}

ENV JAVA_HOME "/usr/lib/jvm/java-8-oracle"

RUN /usr/bin/wget -O /root/auth-parent.tar.gz https://codeload.github.com/USGS-CIDA/cida-auth/tar.gz/auth-parent-${AUTH_VERSION} 

RUN mkdir /liquibase

RUN /bin/tar xzfv /root/auth-parent.tar.gz --strip-components=1 -C /liquibase  && \
	rm /root/auth-parent.tar.gz

COPY liquibase-settings.xml /liquibase/liquibase-settings.xml

WORKDIR /liquibase/auth-database

RUN mvn install -Dmaven.repo.local=/.m2/repository

COPY liquibase.sh /docker-entrypoint-initdb.d/liquibase.sh

WORKDIR /

RUN chown -R postgres:postgres /liquibase && \
	chown -R postgres:postgres /.m2