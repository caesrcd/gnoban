# Installing systemd on Linux Systems

This guide provides a straightforward process for installing and running **GNOBAN** on Linux systems using systemd. Follow the steps below to properly configure the service.

## Installation Steps

### 1. Create System User

Create a dedicated user to run GNOBAN without shell access or home directory.

```bash
sudo useradd -r -M -d / -s /sbin/nologin gnoban
```

### 2. Download and Install Binary

Download the latest release from the [GNOBAN releases page](https://github.com/caesrcd/gnoban/releases).

```bash
tar xzf gnoban-*-linux-gnu.tar.gz
sudo install gnoban-*/gnoban /usr/local/bin/
```

Verify the installation:

```bash
gnoban --version
```

### 3. Install Configuration Files

Clone the repository and copy the required configuration files.

```bash
git clone --depth 1 https://github.com/caesrcd/gnoban.git
cd gnoban/linux/
sudo mkdir -p /etc/gnoban
sudo cp gnoban.conf /etc/gnoban/
sudo cp gnoban.service /etc/systemd/system/
```

### 4. Configure Service Parameters

Edit `/etc/gnoban/gnoban.conf` to set the desired runtime arguments.

```bash
sudo nano /etc/gnoban/gnoban.conf
```

See `gnoban --help` for information on available options and criteria.

### 5. Enable and Start Service

Reload systemd configuration and enable the service to start on boot.

```bash
sudo systemctl daemon-reload
sudo systemctl enable gnoban --now
```

## Service Management

### Check Service Status

```bash
systemctl status gnoban
```

### View Logs

Monitor real-time logs:

```bash
tail -f /var/log/gnoban/debug.log
```

View systemd journal:

```bash
journalctl -u gnoban -f
```
