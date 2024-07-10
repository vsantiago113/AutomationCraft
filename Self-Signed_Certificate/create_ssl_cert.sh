#!/bin/bash

# Generate a self-signed SSL certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout selfsigned.key -out selfsigned.crt

# Check if the command was successful
if [ $? -eq 0 ]; then
    echo "SSL certificate successfully created."
    echo "Key file: selfsigned.key"
    echo "Certificate file: selfsigned.crt"
else
    echo "Failed to create SSL certificate."
fi

# Make the Script Executable: chmod +x create_ssl_cert.sh
# Run the Script: ./create_ssl_cert.sh
