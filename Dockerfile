# Use a light version of the Nginx web server
FROM nginx:alpine

# Copy your index.html into the Nginx default html directory
COPY index.html /usr/share/nginx/html/index.html

# ADDED: Copy your logo into the Nginx default html directory
COPY logo.png /usr/share/nginx/html/logo.png

# Expose port 80 to access the website
EXPOSE 80
