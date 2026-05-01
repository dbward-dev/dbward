-- migrate:up
CREATE INDEX idx_users_email ON users (email);

-- migrate:down
DROP INDEX idx_users_email;
