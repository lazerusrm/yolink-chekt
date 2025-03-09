# Use an official Python runtime as a parent image (upgraded to 3.11 for latest stable version)
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Install system dependencies for robustness
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage caching
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire application, including templates
COPY . /app/
COPY templates/ /app/templates/

# Expose the Quart app's port
EXPOSE 5000

# Set environment variables for security and performance
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Run the Quart app
CMD ["python", "app.py"]