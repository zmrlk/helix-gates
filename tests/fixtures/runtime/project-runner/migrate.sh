#!/bin/sh
set -eu
for migration in db/migrations/*.sql; do
  psql "$DATABASE_URL" -X -v ON_ERROR_STOP=1 -f "$migration"
done
