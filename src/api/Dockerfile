# Extend the existing MCPScan image
FROM mcpscan:latest

# Install API service dependencies
COPY api/requirements.txt /app/api/requirements.txt
RUN pip install --no-cache-dir -r /app/api/requirements.txt

# Copy API service code
COPY api/ /app/api/

# Create directory for SQLite database
RUN mkdir -p /app/data

# Expose the API port
EXPOSE 6000

# Start the API service
CMD ["gunicorn", "--bind", "0.0.0.0:6000", "--workers", "4", "api.app:app"]
