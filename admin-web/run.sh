#!/bin/bash

# ThreatCluster Admin Panel startup script

# Change to the admin-web directory
cd "$(dirname "$0")"

# Activate virtual environment if it exists
if [ -d "../../venv" ]; then
    echo "Activating virtual environment..."
    source ../../venv/bin/activate
elif [ -d "../venv" ]; then
    echo "Activating virtual environment..."
    source ../venv/bin/activate
fi

# Install requirements if needed
if [ ! -f ".requirements_installed" ]; then
    echo "Installing requirements..."
    pip install -r requirements.txt
    touch .requirements_installed
fi

# Export environment variables
export PYTHONPATH="${PYTHONPATH}:$(pwd):$(pwd)/..:$(pwd)/../.."

# Start the admin panel
echo "Starting ThreatCluster Admin Panel on http://localhost:8002"
echo "Make sure you have admin role in Auth0!"
echo ""

# Run with uvicorn
cd app
python main.py