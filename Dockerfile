FROM python:3.10.2-slim-buster

# Create a non-root user to run the application
RUN useradd --create-home rosetta
USER rosetta

# Set the working directory to the user's home directory
WORKDIR /home/rosetta

# Copy the application code into the container
COPY app app
COPY requirements.txt .

# Install the required packages
RUN pip install --no-cache-dir -r requirements.txt

# Set the user and group IDs for the rosetta user
ARG USER_ID=1000
ARG GROUP_ID=1000
RUN if [ ${USER_ID:-0} -ne 0 ] && [ ${GROUP_ID:-0} -ne 0 ]; then \
    if ! getent group rosetta > /dev/null 2>&1; then \
        groupadd -g ${GROUP_ID} rosetta; \
    fi && \
    usermod -u ${USER_ID} -g ${GROUP_ID} rosetta \
;fi

# Add the user's local bin directory to the PATH environment variable
ENV PATH="/home/rosetta/.local/bin:${PATH}"

# Start the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
