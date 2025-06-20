"""
Shared template configuration
"""
import os
from fastapi.templating import Jinja2Templates

# Get template directory
templates_dir = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
    "templates"
)

# Create shared templates instance
templates = Jinja2Templates(directory=templates_dir)