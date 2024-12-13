# Use Python 3.9 slim image
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies and pipx
RUN apt-get update && apt-get install -y \
    gcc \
    python3-pip \
    && pip install pipx \
    && pipx ensurepath \
    && pipx install poetry

# Add Poetry's bin directory to PATH
ENV PATH="/root/.local/bin:$PATH"

# Copy project files
COPY pyproject.toml poetry.lock ./
COPY . .

# Configure Poetry
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi

# Expose port
EXPOSE 8000

# Run with gunicorn
CMD ["poetry", "run", "gunicorn", "--bind", "0.0.0.0:8000", "app:app"] 