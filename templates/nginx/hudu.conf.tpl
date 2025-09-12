server {
    listen 80;
    server_name {{DOMAIN}};
    
    {% if ssl_enabled %}
    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name {{DOMAIN}};
    
    # SSL Configuration
    ssl_certificate /etc/ssl/certs/{{DOMAIN}}.crt;
    ssl_certificate_key /etc/ssl/private/{{DOMAIN}}.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    {% endif %}

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
    {% if ssl_enabled %}
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    {% endif %}

    # Client max body size for file uploads
    client_max_body_size 100M;

    # Hudu proxy configuration
    location / {
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Host $host;
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts for long operations
        proxy_connect_timeout 300s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
        
        # Buffer settings
        proxy_buffering on;
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;
        proxy_temp_file_write_size 256k;
    }

    # WebSocket support for real-time features
    location /cable {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }

    # API routes
    location /api/ {
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Host $host;
        proxy_pass http://127.0.0.1:3000;
        
        # API specific timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # File uploads
    location /uploads {
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Host $host;
        proxy_pass http://127.0.0.1:3000;
        
        # Extended timeout for uploads
        proxy_connect_timeout 600s;
        proxy_send_timeout 600s;
        proxy_read_timeout 600s;
    }

    # Cache static assets
    location ~* ^/assets/ {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        
        # Long-term caching for assets
        expires 1y;
        add_header Cache-Control "public, immutable";
        access_log off;
    }

    # Cache images and media
    location ~* \.(css|gif|ico|jpeg|jpg|js|png|svg|webp|woff|woff2|ttf|eot|pdf|mp4|webm)$ {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        
        expires 1M;
        add_header Cache-Control "public";
        access_log off;
    }

    # Security
    location ~ /\.ht {
        deny all;
    }

    location ~* \.(htaccess|htpasswd|ini|phps|fla|psd|log|sh)$ {
        deny all;
    }

    # Block access to sensitive files
    location ~* \.(yml|yaml|conf|config|bak|backup|swp|tmp)$ {
        deny all;
    }

    # Rate limiting for login endpoints
    location ~* /(login|signin|users/sign_in) {
        limit_req zone=login burst=5 nodelay;
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Host $host;
    }

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types
        application/atom+xml
        application/javascript
        application/json
        application/ld+json
        application/manifest+json
        application/rss+xml
        application/vnd.geo+json
        application/vnd.ms-fontobject
        application/x-font-ttf
        application/x-web-app-manifest+json
        application/xhtml+xml
        application/xml
        font/opentype
        image/bmp
        image/svg+xml
        image/x-icon
        text/cache-manifest
        text/css
        text/plain
        text/vcard
        text/vnd.rim.location.xloc
        text/vtt
        text/x-component
        text/x-cross-domain-policy;

    # Logs
    access_log /var/log/nginx/{{DOMAIN}}_access.log;
    error_log /var/log/nginx/{{DOMAIN}}_error.log;
}

# Rate limiting zones (define in main nginx.conf)
# http {
#     limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
# }