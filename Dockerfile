FROM python:3.9-slim

# Set working directory
WORKDIR .

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV PORT=8019

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Copy the application
COPY . .

# Create logs directory
RUN mkdir -p logs

# Expose port 8019
EXPOSE 8019

# Start the application on port 8019
CMD ["python", "app.py"]
