# Use a light version of the Nginx web server
FROM nginx:alpine

# Copy your index.html into the Nginx default html directory
COPY index.html /usr/share/nginx/html/index.html

# Expose port 80 to access the website
EXPOSE 80

# Startup command: Replaces the placeholder text with the Render Secret environment variable,
# then starts Nginx.
CMD sed -i "s|__GROQ_API_KEY__|${GROQ_API_KEY}|g" /usr/share/nginx/html/index.html && nginx -g 'daemon off;'
