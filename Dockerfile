FROM node:22-alpine
WORKDIR /app
COPY package.json server.js ./
COPY public ./public
ENV NODE_ENV=production PORT=3000 HOST=0.0.0.0 DATA_DIR=/data
RUN mkdir -p /data && chown -R node:node /data /app
USER node
# (sem a instrução VOLUME: o volume é declarado no docker-compose.yml ou na hospedagem; o Railway recusa VOLUME)
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD wget -qO- http://127.0.0.1:3000/api/health || exit 1
CMD ["node", "server.js"]
