# Use the official Python image as a base
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the server script into the container
COPY server.py .

# Install Flask and requests module
RUN pip install Flask requests

# Expose port 5000 for the server
EXPOSE 5000

# Run the server script when the container starts
CMD ["python", "server.py"]
