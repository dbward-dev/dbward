-- migrate:up
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT
);

-- migrate:down
DROP TABLE users;
