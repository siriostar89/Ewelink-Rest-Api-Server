FROM node:latest

# Create app directory
WORKDIR /usr/src/app

# Bundle app source
COPY . ./
RUN mv ./server/* ./ && rm -rf ./server

# Add permissions
RUN chmod --recursive +rwx ./*

# Install dependencies
RUN npm ci --only=production

# communication port
EXPOSE 3000

# Start the server
CMD [ "node", "./server.js" ]