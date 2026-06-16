# Sample init scripts and service configuration

Sample scripts and configuration files for systemd and OpenRC can be found in the [init](../init) folder.

    init/gnoban.service:    systemd service unit configuration
    init/gnoban.openrc:     OpenRC service script
    init/gnoban.openrcconf: OpenRC conf.d file

## Service User

The Linux startup configurations assume the existence of a "gnoban" user and group. They must be created before attempting to use these scripts.

To create a service user without shell access, run:

```bash
sudo useradd -r -d /var/cache/gnoban -s /sbin/nologin gnoban
```

## Paths

### Linux

The configurations assume several paths that might need to be adjusted.

    Binary:              /usr/local/bin/gnoban
    Configuration file:  /etc/gnoban/gnoban.toml
    Logs directory:      /var/log/gnoban
    Cache directory:     /var/cache/gnoban

The cache directory and logs directory should both be owned by the gnoban user and group. It is advised for security reasons to make the configuration file only readable by the gnoban user and group.

NOTE: When using the systemd .service file, the creation of the aforementioned directories and the setting of their permissions is automatically handled by systemd.

## Installing Service Configuration

### systemd

Installing this .service file consists of just copying it to /etc/systemd/system directory, followed by the command `systemctl daemon-reload` in order to update running systemd configuration.

To test, run `systemctl start gnoban` and to enable for system startup run `systemctl enable gnoban`

### OpenRC

Rename gnoban.openrc to gnoban and drop it in /etc/init.d. Double check ownership and permissions and make it executable. Test it with `/etc/init.d/gnoban start` and configure it to run on startup with `rc-update add gnoban`
