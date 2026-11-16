# DevSecOps - Sesión 1: Control de Versiones, Pipelines Iniciales y Docker Seguro

Este documento resume el laboratorio para preparar una EC2 en AWS, crear un repositorio GitHub, configurar CI con GitHub Actions y validar un contenedor Docker seguro.

## 1) Crear la instancia EC2 en AWS

- AMI: Ubuntu Server 24.04 LTS
- Tipo: `t3.small`
- Key Pair: genera un archivo `.pem`
- Security Group:
  - SSH (22) desde `0.0.0.0/0`
  - TCP 3000 desde `0.0.0.0/0`

Conéctese por SSH:

```bash
ssh -i tu-clave.pem ubuntu@<IP_PUBLICA>
```

## 2) Instalar dependencias base

```bash
sudo apt-get update -y
sudo apt-get install -y curl git build-essential

curl -sL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

sudo apt-get install -y docker.io
sudo usermod -aG docker ubuntu
newgrp docker
```

## 3) Crear la app de ejemplo

```bash
mkdir -p ~/devsecops-app/src
cd ~/devsecops-app
```

`package.json`

```bash
cat <<'EOF' > package.json
{
  "name": "devsecops-app",
  "version": "1.0.0",
  "description": "Aplicacion base para Unidad 3",
  "main": "src/index.js",
  "scripts": {
    "start": "node src/index.js"
  },
  "dependencies": {
    "express": "^4.19.2"
  }
}
EOF
```

`src/index.js`

```bash
cat <<'EOF' > src/index.js
const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

app.get('/', (req, res) => {
  res.json({ status: 'OK', message: 'Servidor seguro operando correctamente' });
});

app.listen(PORT, () => {
  console.log(`App corriendo en puerto ${PORT}`);
});
EOF
```

Instalar dependencias:

```bash
npm install
```

## 4) Inicializar Git y conectarlo a GitHub

Crear un repositorio público en GitHub, por ejemplo `devsecops-lab1`, sin README ni `.gitignore`.

```bash
cd ~/devsecops-app
git init
git branch -M main
git add .
git commit -m "Commit inicial: Estructura base de la aplicacion"
git remote add origin https://github.com/TU-USUARIO/devsecops-lab1.git
git push -u origin main
```

Cuando GitHub pida credenciales, usar un PAT o autenticación con `gh auth login`.

## 5) Crear un pipeline base con GitHub Actions

```bash
mkdir -p ~/devsecops-app/.github/workflows
```

```bash
cat <<'EOF' > ~/devsecops-app/.github/workflows/ci.yml
name: DevSecOps CI Pipeline

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  build-and-test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        node-version: [20.x]

    steps:
      - name: Checkout del codigo fuente
        uses: actions/checkout@v4

      - name: Configurar entorno Node.js ${{ matrix.node-version }}
        uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node-version }}
          cache: 'npm'

      - name: Instalar dependencias del proyecto
        run: npm install

      - name: Validar ejecucion del servidor (Prueba rapida)
        run: |
          node src/index.js &
          sleep 2
          curl http://localhost:3000
EOF
```

Subir cambios:

```bash
git add .github/workflows/ci.yml
git commit -m "Agregando pipeline base de GitHub Actions"
git push origin main
```

Verificar en GitHub → `Actions`.

## 6) Crear Dockerfile seguro

```bash
cat <<'EOF' > ~/devsecops-app/Dockerfile
# 1. Usar imagen base oficial, ligera y orientada a seguridad (Alpine Linux)
FROM node:20-alpine

# 2. Crear un directorio de trabajo seguro
WORKDIR /app

# 3. Copiar archivos de dependencias primero para optimizar capas de cache
COPY package*.json ./

# 4. Instalar solo las dependencias de producción necesarias
RUN npm ci --only=production

# 5. Copiar el código fuente restante
COPY src/ ./src/

# 6. BUENA PRÁCTICA CRÍTICA: No ejecutar como usuario root
# Node.js Alpine incluye por defecto un usuario sin privilegios llamado 'node'
USER node

# 7. Exponer el puerto de la aplicación
EXPOSE 3000

# 8. Comando de ejecución por defecto
CMD ["node", "src/index.js"]
EOF
```

`.dockerignore`

```bash
cat <<'EOF' > ~/.dockerignore
node_modules
npm-debug.log
.git
.gitignore
.github
*.pem
*.md
EOF
```

## 7) Construir y probar el contenedor

```bash
cd ~/devsecops-app
docker build -t devsecops-app:latest .
docker run -d --name mi-app-segura -p 3000:3000 devsecops-app:latest
curl http://localhost:3000
docker exec mi-app-segura whoami
```

La salida esperada al ejecutar `whoami` es:

```bash
node
```

Eso confirma que el contenedor no corre como root.

## 8) Validación de CI: fallo y recuperación

### Caso exitoso

```bash
sed -i 's/operando correctamente/validado por CI/g' src/index.js
git add src/index.js
git commit -m "Prueba de funcionamiento de CI"
git push origin main
```

### Caso con error intencional

```bash
echo "codigo_roto_sin_sentido(" >> src/index.js
git add src/index.js
git commit -m "Prueba de fallo intencional"
git push origin main
```

Esto debe fallar en GitHub Actions por un `SyntaxError`. Luego restaurar:

```bash
git revert HEAD --no-edit
git push origin main
```

## 9) Evidencias requeridas

- Captura de la pestaña `Actions` en GitHub ejecutándose en verde.
- Captura de la terminal con `docker exec mi-app-segura whoami` mostrando `node`.

## 10) Resumen

Este ejercicio valida cuatro aspectos clave:

1. Preparación y conexión segura de una EC2 en AWS.
2. Control de versiones con Git/GitHub.
3. Automatización de validación con GitHub Actions.
4. Contenedorización segura con Docker y uso de usuario no privilegiado.
