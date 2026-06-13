# WordPress

WordPress is a first-class workload. Each site runs in its own isolated PHP-FPM
pool and gets a tailored NGINX vhost, with support for single-site, **multisite**,
and **Bedrock** layouts.

## Isolation model

- **One PHP-FPM pool per site** (`templates/php-fpm/pool.conf.tera`) running as a
  dedicated UNIX user, so sites cannot read each other's files or share a process
  pool.
- A per-site NGINX vhost (`templates/nginx/wordpress.conf.tera`) wires PHP
  requests to that pool's socket.

## Layouts

### Single site
Standard WordPress in the web root, served by the WordPress vhost template.

### Multisite
Subdomain or subdirectory multisite, using
`templates/nginx/vhost_wordpress_multisite.tera` and the shared snippet
`templates/nginx/snippets/wordpress_multisite_common.tera` for the multisite
rewrite rules.

### Bedrock
[Bedrock](https://roots.io/bedrock/) lays WordPress out as a Composer project with
the document root at `web/` and configuration in environment files. Point the
site's web root at the Bedrock `web/` directory and use the standard WordPress
vhost; PHP-FPM isolation is unchanged.

## TLS

Issued via [ACME](../api/README.md#ssl); DNS-01 supports wildcards for multisite
subdomains.

## Securing the site

WordPress is the most-attacked workload GhostCP hosts. Two planned layers guard
it at the edge, before PHP runs:

- **[Threat feeds](../security/threat-feeds.md)** — imported IP blocklists `403`
  known-bad sources fleet-wide; `wp-login.php`/`xmlrpc.php` are common targets.
- **[CrowdSec](../security/crowdsec.md)** — detects brute force/credential
  stuffing in the logs and bans via the NGINX + firewall bouncers.

## Status

NGINX and PHP-FPM templates (including multisite) exist. End-to-end WordPress
provisioning (pool creation, vhost apply, WP install) from the API is planned —
see the [status table](../../README.md#status).
