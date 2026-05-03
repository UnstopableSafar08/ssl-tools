FROM node:22-alpine

WORKDIR /app

# Copy app files
COPY index.html /app/index.html
COPY assets/ /app/assets/

# Expose port 8080
EXPOSE 8080

# Start local static server with SSL checker endpoint
CMD ["node", "assets/js/server.js"]
