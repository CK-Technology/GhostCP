# Websites

GhostCP targets two web workloads as first-class citizens: **static sites** and
**WordPress**. Both are provisioned from NGINX (and, for PHP, PHP-FPM) templates.

- [Static Sites](static-sites.md) — NGINX vhosts, automatic TLS
- [WordPress](wordpress.md) — isolated PHP-FPM pools, multisite, Bedrock

## How it fits together

- A **web domain** record in PostgreSQL describes the site.
- The matching [template](../architecture/templating.md) renders an NGINX vhost
  (and a PHP-FPM pool for PHP sites).
- TLS is issued via [ACME / Let's Encrypt](../api/README.md#ssl).

## API

See the [web domain routes](../api/README.md#web-domains).

## Status

NGINX and PHP-FPM templates exist (`templates/nginx/`, `templates/php-fpm/`) and
the rendering modules are implemented. End-to-end provisioning from the
web-domain handlers is in progress — see the
[status table](../../README.md#status).
