#!/bin/bash
# =============================================================================
# setup-local.sh — Set up ServiceNow MCP for local development
# =============================================================================
# Usage: bash scripts/setup-local.sh
# =============================================================================

set -e

echo "=== ServiceNow MCP — Local Setup ==="
echo ""

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "ERROR: python3 is not installed. Please install Python 3.11+."
    exit 1
fi

PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "Python version: $PYTHON_VERSION"

# Create virtual environment
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
    echo "Virtual environment created at .venv/"
else
    echo "Virtual environment already exists at .venv/"
fi

# Activate and install
echo "Installing dependencies..."
source .venv/bin/activate
pip install --upgrade pip -q
pip install -e . -q
echo "Dependencies installed."

# Create .env from template if it doesn't exist
if [ ! -f ".env" ]; then
    if [ -f ".env.local.template" ]; then
        cp .env.local.template .env
        echo ""
        echo "Created .env from template. Please edit it with your ServiceNow credentials:"
        echo "  nano .env"
        echo ""
    fi
else
    echo ".env already exists."
fi

# Test the installation
echo ""
echo "Verifying installation..."
if command -v servicenow-mcp &> /dev/null; then
    echo "  servicenow-mcp CLI: OK"
else
    echo "  servicenow-mcp CLI: NOT FOUND (try: source .venv/bin/activate)"
fi

if command -v servicenow-mcp-sse &> /dev/null; then
    echo "  servicenow-mcp-sse CLI: OK"
else
    echo "  servicenow-mcp-sse CLI: NOT FOUND"
fi

echo ""
echo "=== Setup complete! ==="
echo ""
echo "Next steps:"
echo "  1. Edit .env with your ServiceNow credentials"
echo "  2. Add to Claude Desktop config (Settings → Developer → Edit Config):"
echo ""
echo '     {
       "mcpServers": {
         "servicenow": {
           "command": "python",
           "args": ["-m", "servicenow_mcp.cli"],
           "cwd": "'$(pwd)'",
           "env": {
             "DOTENV_PATH": "'$(pwd)'/.env"
           }
         }
       }
     }'
echo ""
echo "  3. Restart Claude Desktop"
echo "  4. You should see ServiceNow tools available in your conversation"
echo ""
