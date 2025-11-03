-- init-db.sql
IF NOT EXISTS (SELECT name FROM sys.databases WHERE name = N'keycloak')
BEGIN
    CREATE DATABASE [keycloak];
END;