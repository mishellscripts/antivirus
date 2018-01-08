/* Creation of the database */
DROP DATABASE IF EXISTS malwaredb;
CREATE DATABASE malwaredb;
USE malwaredb;

/* Creation of the tables */
CREATE TABLE malware (
	name VARCHAR(32),
	signature VARCHAR(20),
	PRIMARY KEY (name, signature)
);

CREATE TABLE admin (
	username VARCHAR(32) NOT NULL PRIMARY KEY,
    password VARCHAR(32) NOT NULL
);