FROM python:3.12-slim

# Create non-root user
RUN groupadd -r sysfox && useradd -r -g sysfox -m sysfox

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY sysfox_ai/ sysfox_ai/
COPY soul.md .

# Switch to non-root user
USER sysfox

EXPOSE 8000

CMD ["python", "-m", "sysfox_ai"]
