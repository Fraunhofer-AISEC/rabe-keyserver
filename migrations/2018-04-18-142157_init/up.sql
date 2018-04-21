-- Your SQL goes here
create table users (
	id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    username varchar(255) NOT NULL,
    password varchar(255) NOT NULL,
    salt integer NOT NULL,
    api_key varchar(255) NOT NULL
)