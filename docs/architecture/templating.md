# Templating

GhostCP generates native service configuration from [Tera](https://keats.github.io/tera/)
templates. Desired state lives in PostgreSQL; templates render it into the config
files that NGINX, PHP-FPM, and the mail stack consume.

## Template tree

Templates live under `templates/`:

```
templates/
├── nginx/
│   ├── vhost.conf.tera                 # generic vhost
│   ├── static.conf.tera                # static-site vhost
│   ├── proxy.conf.tera                 # reverse-proxy vhost
│   ├── wordpress.conf.tera             # WordPress vhost
│   ├── vhost_standard.tera
│   ├── vhost_wordpress_multisite.tera  # WP multisite
│   └── snippets/
│       └── wordpress_multisite_common.tera
├── php-fpm/
│   ├── pool.conf.tera                  # per-site FPM pool
│   └── pool.tera
└── docker/                             # app-specific compose templates
```

The rendering modules are in `api/src/templates/`:

- `nginx.rs` — vhost generation
- `php_fpm.rs` — per-site pool generation
- `postfix.rs`, `dovecot.rs` — mail config (modules present; mail provisioning
  is staged)

## How it works

1. A handler resolves the desired state for a resource (e.g. a web domain) from
   PostgreSQL.
2. The matching Tera template is rendered with that context.
3. The output is written to the configured target directory (`NGINX_CONFIG_DIR`,
   etc.) and the service is reloaded.

`TEMPLATES_DIR` selects the template root; the per-service output paths are
configured via the variables in [configuration](../getting-started/configuration.md).

## Status

NGINX and PHP-FPM templates exist and the rendering modules are implemented. The
**DNS** path is fully wired end-to-end. Wiring the web-domain and mail handlers
to render-and-apply these templates is in progress — see the
[status table](../../README.md#status).
