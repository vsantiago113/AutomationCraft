# Define common variables
$HOST = "0.0.0.0"
$PORT = "8000"
$SSL_KEYFILE = "selfsigned.key"
$SSL_CERTFILE = "selfsigned.crt"
$SECURE_APP = "mock_servicenow_secure:app"
$SIMPLE_APP = "mock_servicenow_simple:app"

# Function to run the secure app with SSL
function Run-SecureSSL {
    Write-Output "Running secure version with SSL..."
    uvicorn $SECURE_APP --reload --host $HOST --port $PORT --ssl-keyfile $SSL_KEYFILE --ssl-certfile $SSL_CERTFILE --log-level debug
    if ($LASTEXITCODE -ne 0) {
        Write-Output "Failed to start secure version of Uvicorn with SSL"
        exit 1
    }
}

# Function to run the secure app without SSL
function Run-SecureNoSSL {
    Write-Output "Running secure version without SSL..."
    uvicorn $SECURE_APP --reload --host $HOST --port $PORT --log-level debug
    if ($LASTEXITCODE -ne 0) {
        Write-Output "Failed to start secure version of Uvicorn without SSL"
        exit 1
    }
}

# Function to run the simple app with SSL
function Run-SimpleSSL {
    Write-Output "Running simple version with SSL..."
    uvicorn $SIMPLE_APP --reload --host $HOST --port $PORT --ssl-keyfile $SSL_KEYFILE --ssl-certfile $SSL_CERTFILE --log-level debug
    if ($LASTEXITCODE -ne 0) {
        Write-Output "Failed to start simple version of Uvicorn with SSL"
        exit 1
    }
}

# Function to run the simple app without SSL
function Run-SimpleNoSSL {
    Write-Output "Running simple version without SSL..."
    uvicorn $SIMPLE_APP --reload --host $HOST --port $PORT --log-level debug
    if ($LASTEXITCODE -ne 0) {
        Write-Output "Failed to start simple version of Uvicorn without SSL"
        exit 1
    }
}

# Convert arguments to lowercase
$ARG1 = $args[0].ToLower()
$ARG2 = $args[1].ToLower()

# Debug statement to print the arguments
Write-Output "Arguments passed: $ARG1 $ARG2"

# Check arguments to decide which version to run
if ($ARG1 -eq "secure") {
    if ($ARG2 -eq "ssl") {
        Run-SecureSSL
    } else {
        Run-SecureNoSSL
    }
} elseif ($ARG1 -eq "simple") {
    if ($ARG2 -eq "ssl") {
        Run-SimpleSSL
    } else {
        Run-SimpleNoSSL
    }
} else {
    Write-Output "Invalid arguments. Usage: .\run_uvicorn.ps1 [secure/simple] [ssl]"
    exit 1
}
