FROM node:20-slim
WORKDIR /app

# Install dependencies first (this layer only rebuilds when they change)
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund || npm install --omit=dev --no-audit --no-fund

# App code + static pages
COPY server.js ./
COPY public ./public

ENV NODE_ENV=production
USER node
CMD ["node", "server.js"]
