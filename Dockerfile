# Dockerfile
FROM python:3.9-slim

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY node.py .
COPY client_wallet.py .
COPY blockchain_client.py .

# Expose ports for nodes and client
EXPOSE 8000 8001 8002 8003

CMD ["uvicorn", "node:app", "--host", "0.0.0.0", "--port", "8000"]