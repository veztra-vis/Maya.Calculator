# Use Node.js
FROM node:18-alpine

# Set working directory
WORKDIR /app

# Copy package.json and install dependencies
COPY package.json ./
RUN npm install

# Copy the rest of the files
COPY server.js ./
COPY public ./public

# Expose the port Render uses
EXPOSE 10000

# Start the server
CMD ["node", "server.js"]
