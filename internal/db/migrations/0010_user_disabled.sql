-- 0010_user_disabled.sql: a disabled account cannot log in and its
-- sessions stop working; the account and its audit history are kept.
ALTER TABLE users ADD COLUMN disabled boolean NOT NULL DEFAULT false;
