# DevSecOps Lab 1

Proyecto base para el laboratorio de DevSecOps: GitHub + GitHub Actions + Docker seguro.

## Ejecutar localmente

```bash
npm install
npm start
```

## Docker

```bash
docker build -t devsecops-app:latest .
docker run -d --name mi-app-segura -p 3000:3000 devsecops-app:latest
curl http://localhost:3000
docker exec mi-app-segura whoami
```

La salida de `docker exec mi-app-segura whoami` debe ser `node`.

## GitHub Actions

El workflow en `.github/workflows/ci.yml` valida que la aplicación puede iniciar y responder en el puerto 3000.
