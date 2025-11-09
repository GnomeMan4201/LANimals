#!/bin/bash
echo "=== Running Black Code Formatter ==="
find . -name "*.py" -exec black {} \;
echo "=== Running Import Sorter ==="
find . -name "*.py" -exec isort {} \;
echo "=== Running Flake8 Linter ==="
find . -name "*.py" -exec flake8 {} \;
echo "=== Quality Checks Complete ==="
