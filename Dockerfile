# Utilise Node.js 18 en base
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./

RUN npm install --legacy-peer-deps \
    && npm install --save-dev @types/express




# Ajoute les dépendances nécessaires à la compilation native
RUN apk add --no-cache python3 make g++ \
    && npm install --production --legacy-peer-deps \
    && npm cache clean --force


COPY . .

RUN npm run build

EXPOSE 3030

CMD ["node", "dist/main.js"]
