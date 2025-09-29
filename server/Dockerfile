# Use a lightweight Python base image
FROM python:3.12.0-slim-bookworm

# Ensure stdout/stderr are unbuffered and bytecode is not generated
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Set working directory
ENV APP=/app
WORKDIR $APP

# Copy requirements and install
COPY requirements.txt $APP/
RUN pip install --upgrade pip \
    && pip install -r requirements.txt

# Copy the rest of the application code
COPY . $APP

# Make entrypoint executable
RUN chmod +x /app/entrypoint.sh

# Expose the port Django will run on
EXPOSE 8000

# Entrypoint for container
ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]

# Default command to start the Django app
CMD ["gunicorn", "--bind", ":8000", "--workers", "3", "djangoproj.wsgi"]
