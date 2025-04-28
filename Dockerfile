FROM node:18 AS builder

WORKDIR /usr/src/app

COPY package*.json ./
RUN npm install

COPY . .
RUN npm run build

FROM node:18-slim

WORKDIR /usr/src/app

COPY --from=builder /usr/src/app/package*.json ./
RUN npm install --only=production

COPY --from=builder /usr/src/app/dist ./dist
COPY --from=builder /usr/src/app/.env ./.env

ENV PORT=8000

EXPOSE ${PORT}

CMD ["sh", "-c", "node dist/main.js"]