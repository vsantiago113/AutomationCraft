#!/bin/bash

# Define common variables
HOST="0.0.0.0"
PORT="8000"
SSL_KEYFILE="selfsigned.key"
SSL_CERTFILE="selfsigned.crt"
SECURE_APP="mock_servicenow_secure:app"
SIMPLE_APP="mock_servicenow_simple:app"

# Function to run the secure app with SSL
run_secure_ssl() {
    echo "Running secure version with SSL..."
    uvicorn $SECURE_APP --reload --host $HOST --port $PORT --ssl-keyfile $SSL_KEYFILE --ssl-certfile $SSL_CERTFILE --log-level debug
    if [ $? -ne 0 ]; then
        echo "Failed to start secure version of Uvicorn with SSL"
        exit 1
    fi
}

# Function to run the secure app without SSL
run_secure_no_ssl() {
    echo "Running secure version without SSL..."
    uvicorn $SECURE_APP --reload --host $HOST --port $PORT --log-level debug
    if [ $? -ne 0 ]; then
        echo "Failed to start secure version of Uvicorn without SSL"
        exit 1
    fi
}

# Function to run the simple app with SSL
run_simple_ssl() {
    echo "Running simple version with SSL..."
    uvicorn $SIMPLE_APP --reload --host $HOST --port $PORT --ssl-keyfile $SSL_KEYFILE --ssl-certfile $SSL_CERTFILE --log-level debug
    if [ $? -ne 0 ]; then
        echo "Failed to start simple version of Uvicorn with SSL"
        exit 1
    fi
}

# Function to run the simple app without SSL
run_simple_no_ssl() {
    echo "Running simple version without SSL..."
    uvicorn $SIMPLE_APP --reload --host $HOST --port $PORT --log-level debug
    if [ $? -ne 0 ]; then
        echo "Failed to start simple version of Uvicorn without SSL"
        exit 1
    fi
}

# Convert arguments to lowercase
ARG1=$(echo "$1" | tr '[:upper:]' '[:lower:]')
ARG2=$(echo "$2" | tr '[:upper:]' '[:lower:]')

# Debug statement to print the arguments
echo "Arguments passed: $ARG1 $ARG2"

# Check arguments to decide which version to run
if [ "$ARG1" == "secure" ]; then
    if [ "$ARG2" == "ssl" ]; then
        run_secure_ssl
    else
        run_secure_no_ssl
    fi
elif [ "$ARG1" == "simple" ]; then
    if [ "$ARG2" == "ssl" ]; then
        run_simple_ssl
    else
        run_simple_no_ssl
    fi
else
    echo "Invalid arguments. Usage: ./run_uvicorn.sh [secure/simple] [ssl]"
    exit 1
fi

# Make the script executable by running: chmod +x run_uvicorn.sh
# Run the script: ./run_uvicorn.sh [secure/simple] [ssl]
