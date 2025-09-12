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

    root /var/www/{{DOMAIN}};
    index index.php index.html index.htm;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
    {% if ssl_enabled %}
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    {% endif %}

    # WordPress specific rules
    location / {
        try_files $uri $uri/ /index.php$is_args$args;
    }

    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_intercept_errors on;
        fastcgi_pass unix:/var/run/php/php8.1-fpm-{{DOMAIN}}.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param HTTPS {% if ssl_enabled %}on{% else %}off{% endif %};
    }

    # WordPress security
    location ~* /(?:uploads|files)/.*\.php$ {
        deny all;
    }

    location ~ ^/wp-content/uploads/.*\.(html|htm|shtml|php|js|swf)$ {
        deny all;
    }

    # Hide sensitive files
    location ~* \.(htaccess|htpasswd|ini|phps|fla|psd|log|sh)$ {
        deny all;
    }

    location ~ /\.ht {
        deny all;
    }

    location = /xmlrpc.php {
        deny all;
    }

    location ~* /wp-config\.php {
        deny all;
    }

    location ~* /wp-admin/install\.php {
        deny all;
    }

    # Cache static files
    location ~* \.(css|gif|ico|jpeg|jpg|js|png|svg|webp|woff|woff2|ttf|eot)$ {
        expires 1M;
        add_header Cache-Control "public, immutable";
        access_log off;
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