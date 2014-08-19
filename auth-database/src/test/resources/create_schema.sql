-- Creates a schema for which the integration tests will work with
CREATE SCHEMA IF NOT EXISTS ${schemaname} AUTHORIZATION ${runasusername};
SET SCHEMA ${schemaname};
