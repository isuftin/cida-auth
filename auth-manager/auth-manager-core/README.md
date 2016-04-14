#### Build/Deploy Tips

## Container Configuration
When using Postgres JNDI resource block, ensure that you are setting `defaultAutoCommit` to `true`. Not doing so will cause Syncope to be unable to create the tables it needs to function.

Local Docker example:
```
<Resource
	description="token storage database"
	name="jdbc/cidaAuthDS"
	auth="Container"
	type="javax.sql.DataSource"
	username="postgres"
	password="postgres"
	driverClassName="org.postgresql.Driver"
	url="jdbc:postgresql://192.168.99.100:5432/postgres"
	maxActive="50"
	maxIdle="10"
	removeAbandoned="true"
	removeAbandonedTimeout="60"
	logAbandoned="true"
	testOnBorrow="true"
	defaultAutoCommit="true"
	validationQuery="SELECT 1"
	accessToUnderlyingConnectionAllowed="true"
	jdbcInterceptors="org.apache.tomcat.jdbc.pool.interceptor.ConnectionState;org.apache.tomcat.jdbc.pool.interceptor.StatementFinalizer"
	poolPreparedStatements="true"
	maxOpenPreparedStatements="400"
/>
```