FROM tomcat:8.0-jre8

MAINTAINER Ivan Suftin <isuftin@usgs.gov>

ENV AUTH_VERSION ${AUTH_VERSION:-"1.2.5"}

EXPOSE 8080

RUN wget -O /usr/local/tomcat/webapps/auth-manager-core.war "http://cida.usgs.gov/maven/service/local/artifact/maven/redirect?r=cida-public-releases&g=gov.usgs.cida.auth&a=auth-manager-core&v=${AUTH_VERSION}&e=war"

RUN wget -O /usr/local/tomcat/webapps/probe.war "https://github.com/psi-probe/psi-probe/releases/download/3.0.0.M3/probe.war"

RUN mkdir -p /usr/local/tomcat/ssl

ADD https://jdbc.postgresql.org/download/postgresql-9.4.1208.jar /usr/local/tomcat/lib

RUN keytool -genkey -noprompt -keystore /usr/local/tomcat/ssl/.keystore -validity 999 -keysize 2048 -alias auth-manager-core -keyalg RSA -keypass changeit -storepass changeit -dname "CN=auth-manager-core, OU=owi, O=owi, L=middleton, S=WI, C=US" 

RUN keytool -selfcert -alias auth-manager-core  -keypass changeit -dname "CN=auth-manager-core, OU=owi, O=owi, L=middleton, S=WI, C=US" -keystore /usr/local/tomcat/ssl/.keystore -storepass changeit -validity 999

COPY web.xml /usr/local/tomcat/conf/web.xml

COPY server.xml /usr/local/tomcat/conf/server.xml

COPY context.xml /usr/local/tomcat/conf/context.xml

COPY tomcat-users.xml /usr/local/tomcat/conf/tomcat-users.xml

COPY setenv.sh /usr/local/tomcat/bin/setenv.sh 

RUN chmod +x /usr/local/tomcat/bin/setenv.sh

RUN rm -rf /usr/local/tomcat/bin/ROOT

RUN rm -rf /usr/local/tomcat/bin/docs

RUN rm -rf /usr/local/tomcat/bin/examples