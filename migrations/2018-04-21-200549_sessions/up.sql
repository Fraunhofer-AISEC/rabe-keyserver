-- Your SQL goes here
create table sessions (
	id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
	user_id INT NOT NULL,
    session_id TEXT,
    scheme TEXT,
    key_material TEXT,
    is_initialized TINYINT(1),
    FOREIGN KEY (user_id) REFERENCES users(id)
)