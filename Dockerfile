FROM python:3.11-alpine

WORKDIR /app

# Instalação de dependências de build se necessário
RUN apk add --no-cache gcc musl-dev

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Criação de usuário não-privilegiado para conformidade de segurança
RUN addgroup -S devsecops && adduser -S devsecops -G devsecops
USER devsecops

ENTRYPOINT ["python", "auditor_passivo.py"]