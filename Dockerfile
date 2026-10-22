# TataPlay IP-TV Self-Hosted Dockerfile
FROM php:8.2-apache

# Enable required Apache modules
RUN a2enmod rewrite headers

# Allow .htaccess in Apache DocumentRoot and set ServerName
RUN echo "ServerName localhost" >> /etc/apache2/apache2.conf \
    && sed -i '/<Directory \/var\/www\/>/,/<\/Directory>/ s/AllowOverride None/AllowOverride All/' /etc/apache2/apache2.conf

# Set working directory
WORKDIR /var/www/html

# Copy repository files
COPY . /var/www/html/

# Create app/data directory with proper write permissions for www-data
RUN mkdir -p /var/www/html/app/data \
    && chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html \
    && chmod -R 777 /var/www/html/app \
    && chmod -R 777 /var/www/html/app/data

EXPOSE 80

CMD ["apache2-foreground"]
