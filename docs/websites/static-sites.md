# Static Sites

Static sites are the simplest workload: NGINX serves files from a web root with
TLS and HTTP/2, no application runtime.

## Template

Static-site vhosts render from `templates/nginx/static.conf.tera`. A rendered
vhost typically:

- serves from the site's web root with an `index` fallback,
- redirects HTTP → HTTPS,
- enables HTTP/2 and HSTS,
- writes per-site access/error logs.

## Provisioning flow

1. Create a web domain (see [API](../api/README.md#web-domains)) with a static
   template.
2. GhostCP renders the NGINX vhost from the static template and writes it to
   `NGINX_CONFIG_DIR`.
3. TLS is requested via [ACME](../api/README.md#ssl) and the vhost is reloaded.

## TLS

Certificates are issued through Let's Encrypt. DNS-01 (via a configured DNS
provider) supports wildcards; HTTP-01 is available for single hosts. See the
[SSL routes](../api/README.md#ssl).

## Status

Templates exist and render. Wiring the create-domain handler to render-and-apply
plus auto-TLS is in progress — see the [status table](../../README.md#status).
