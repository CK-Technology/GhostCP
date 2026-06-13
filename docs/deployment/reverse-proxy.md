# Reverse Proxy

In any non-local deployment, run the GhostCP API behind a TLS-terminating reverse
proxy. The API speaks plain HTTP and ships with permissive CORS in the current
build, so it should not be exposed directly.

## NGINX example

```nginx
server {
    listen 443 ssl http2;
    server_name panel.example.com;

    ssl_certificate     /etc/ghostcp/ssl/panel.example.com/fullchain.pem;
    ssl_certificate_key /etc/ghostcp/ssl/panel.example.com/privkey.pem;
    add_header Strict-Transport-Security "max-age=31536000" always;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    server_name panel.example.com;
    return 301 https://$host$request_uri;
}
```

Adjust `proxy_pass` to match the API `PORT`. The panel's own certificate can be
issued through [ACME](../dns/acme.md) like any other site.

## Notes

- Terminate TLS at the proxy; keep the API bound to `127.0.0.1`.
- Forward `X-Forwarded-*` headers so the API sees the real client and scheme.
