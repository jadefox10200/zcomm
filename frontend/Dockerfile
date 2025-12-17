# Build stage
FROM node:20-alpine AS builder
WORKDIR /app

COPY package*.json ./
# Install dependencies using npm ci and relax dependency resolution
RUN npm ci --legacy-peer-deps

COPY . .
RUN npm run build

# Production stage - serve with nginx
FROM nginx:alpine
COPY --from=builder /app/build /usr/share/nginx/html
EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]