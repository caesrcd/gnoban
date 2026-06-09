# Installation from source

## Dependencies

Install [recent Python](https://www.python.org/downloads/) (3.11+).

## Clone and setup

```bash
cd /opt
git clone https://github.com/caesrcd/gnoban
cd gnoban
python -m venv .env
source .env/bin/activate
pip install -r requirements.txt
```

## Install wrapper script

Create an executable wrapper at `/usr/local/bin/gnoban` to invoke the application with the recommended Python flags:

```bash
sudo tee /usr/local/bin/gnoban > /dev/null << 'EOF'
#!/usr/bin/env sh
set -e

# Python optimization
export PYTHONOPTIMIZE=2
export PYTHONUNBUFFERED=1
export PYTHONDONTWRITEBYTECODE=1
export PYTHONFAULTHANDLER=1
export PYTHONUTF8=1

# Virtual environment
export VIRTUAL_ENV=/opt/gnoban/.env
export PATH=/opt/gnoban/.env/bin:$PATH

# Execute application
exec python /opt/gnoban/gnoban.py "$@"
EOF
sudo chmod +x /usr/local/bin/gnoban
```

To test, run `gnoban --help`.
