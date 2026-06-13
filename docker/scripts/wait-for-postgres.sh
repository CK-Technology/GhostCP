#!/bin/sh
# Block until Postgres accepts connections before starting the API.
# Host networking: Postgres is reachable on localhost:5432.
set -e

host="${POSTGRES_HOST:-localhost}"
port="${POSTGRES_PORT:-5432}"
user="${POSTGRES_USER:-ghostcp}"

until pg_isready -h "$host" -p "$port" -U "$user" >/dev/null 2>&1; do
  echo "Waiting for Postgres at ${host}:${port}..."
  sleep 1
done

echo "Postgres is ready."
