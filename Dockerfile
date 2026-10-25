# Servidor Controle Ceasa (só a API: contas e sincronização). O app fica no Netlify.
FROM node:22-alpine
WORKDIR /app
COPY package.json server.js ./
ENV NODE_ENV=production HOST=0.0.0.0 DATA_DIR=/data
CMD ["node", "server.js"]
