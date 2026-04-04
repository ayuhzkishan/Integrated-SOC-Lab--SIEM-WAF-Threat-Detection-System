FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY attack_simulator.py .

# Wait for web server to be ready, then start attack campaign
CMD ["python", "-u", "attack_simulator.py"]
