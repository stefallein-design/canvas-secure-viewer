FROM node:22-bookworm

# Poppler tools for pdfinfo + pdftoppm
RUN apt-get update && apt-get install -y poppler-utils \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install

COPY . .

ENV NODE_ENV=production
EXPOSE 3000

CMD ["npm", "start"]
