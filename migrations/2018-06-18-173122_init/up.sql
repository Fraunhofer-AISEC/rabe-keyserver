-- Your SQL goes here
create table sessions (
	id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    random_session_id TEXT,
    scheme TEXT,
    key_material TEXT,
    attributes TEXT,
    is_initialized TINYINT(1)
);

create table users (
	id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    session_id INT NOT NULL,
    username varchar(255) NOT NULL,
    password varchar(255) NOT NULL,
    attributes TEXT,
    salt integer NOT NULL,
    api_key varchar(255) NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);
