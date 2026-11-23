-- migrate:up
CREATE TABLE runtime_items(id integer PRIMARY KEY);
-- migrate:down
DROP TABLE runtime_items;
