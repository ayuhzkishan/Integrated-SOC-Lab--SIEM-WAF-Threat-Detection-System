FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir flask>=3.0.0

COPY webhook_receiver.py .

EXPOSE 5000

CMD ["python", "-u", "webhook_receiver.py"]
