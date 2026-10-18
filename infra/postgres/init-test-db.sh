#!/bin/sh
# Creates the integration-test database alongside the dev database on first container start.
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
CREATE DATABASE noc_test OWNER noc;
SQL
