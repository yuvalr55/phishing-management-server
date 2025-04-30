# Development image with source code
FROM node:18-alpine

# Set working directory
WORKDIR /usr/src/app

# Install build dependencies
RUN apk add --no-cache make gcc g++ python3 git

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci
RUN npm uninstall bcrypt && npm install bcrypt --build-from-source

# Copy source files
COPY . .

# Set environment variables
ENV NODE_ENV=production
EXPOSE 8000

# Use ts-node to run the application directly from TypeScript
CMD ["npx", "ts-node", "src/main.ts"]