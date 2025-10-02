#!/bin/bash
echo "=== Quickstart Demo ==="
echo "Repository: $(basename $(git rev-parse --show-toplevel))"
echo "Safe demonstration mode"
python --version 2>/dev/null || echo "Python check skipped"
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt >/dev/null 2>&1 && echo "Dependencies installed"
fi
echo "Demo completed - see README.md for full usage"
