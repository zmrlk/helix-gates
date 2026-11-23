-- Deliberate synthetic regression: this file must roll back.
CREATE TABLE rolled_back (id integer);
SELECT * FROM deliberately_missing_relation;
