# ============================================
# Apache 2.4 + ModSecurity WAF + PHP 8
# ============================================
FROM php:8.2-apache

# Install ModSecurity and dependencies
RUN apt-get update && apt-get install -y \
    libapache2-mod-security2 \
    modsecurity-crs \
    libxml2-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Enable required Apache modules
RUN a2enmod security2 rewrite headers

# ---- ModSecurity Configuration ----
# Copy base config
COPY modsec/modsecurity.conf /etc/modsecurity/modsecurity.conf

# Copy CRS setup
COPY modsec/crs-setup.conf /etc/modsecurity/crs-setup.conf

# Copy custom rules
COPY modsec/custom_rules/ /etc/modsecurity/custom_rules/

# Build the modsecurity include chain
RUN echo 'Include "/etc/modsecurity/modsecurity.conf"' > /etc/apache2/mods-enabled/security2.conf && \
    echo 'Include "/etc/modsecurity/crs-setup.conf"' >> /etc/apache2/mods-enabled/security2.conf && \
    echo 'Include "/usr/share/modsecurity-crs/rules/*.conf"' >> /etc/apache2/mods-enabled/security2.conf && \
    echo 'Include "/etc/modsecurity/custom_rules/*.conf"' >> /etc/apache2/mods-enabled/security2.conf

# ---- Apache Logging Config ----
# Use combined log format and log everything for SIEM
RUN echo 'LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined' > /etc/apache2/conf-enabled/logging.conf && \
    echo 'ErrorLog /var/log/apache2/error.log' >> /etc/apache2/conf-enabled/logging.conf && \
    echo 'CustomLog /var/log/apache2/access.log combined' >> /etc/apache2/conf-enabled/logging.conf

# Create log dirs
RUN mkdir -p /var/log/apache2 /var/log/modsec && \
    chown -R www-data:www-data /var/log/apache2 /var/log/modsec

# ---- Deploy Vulnerable Application ----
COPY app/ /var/www/html/

# Fix permissions
RUN chown -R www-data:www-data /var/www/html

EXPOSE 80

CMD ["apache2-foreground"]
