# Use the official Node.js image as the base image
FROM docker.arvancloud.ir/node:latest AS build

# Set the working directory
WORKDIR /app

# Copy package.json and package-lock.json
COPY package.json package-lock.json ./

# Install dependencies
RUN npm install

# Copy the rest of the application code
COPY ../.. .

# Build the application
RUN npm run build

# Use a lightweight web server to serve the application
FROM docker.arvancloud.ir/nginx:alpine

# Copy the built application from the build stage
COPY --from=build /app/dist /usr/share/nginx/html

COPY ./nginx.conf ./conf.d/default.conf

# Expose the port that Nginx will run on
EXPOSE 80

# Start Nginx
CMD ["nginx", "-g", "daemon off;"]

