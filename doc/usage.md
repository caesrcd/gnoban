# Usage

## Dependencies

Install [latest Bitcoin Core](https://bitcoincore.org/en/download/).

## Connecting to your Bitcoin node

If you run GNOBAN on the same computer as your Bitcoin node, it will automatically detect the configuration file (`bitcoin.conf`) in the default directory.

If your configuration file is in a non-default location, specify the correct path using the `-btcdir` argument:

```bash
gnoban -btcdir /path/to/bitcoin/ ...
```

If you are running GNOBAN on another computer, specify the IP address and port of your Bitcoin node along with the RPC credentials:

```bash
gnoban -rpcurl http://username:password@192.168.0.10:8332 ...
```

## Command-line examples

Ban nodes running Bitcoin Knots:

```bash
gnoban -u 'Knots'
```

Ban nodes with a specific service flag:

```bash
gnoban -s 27
```

Ban nodes running an outdated protocol version:

```bash
gnoban -v 70015 70014
```

Ban nodes using v1 transport only:

```bash
gnoban -t v1
```

Ban nodes with a minfeefilter above a threshold (BTC/kvB):

```bash
gnoban -m 0.000009
```

Combine multiple criteria (any match will ban the node):

```bash
gnoban -u 'Knots' -s 26 -t v1
```

Use a complex filter expression:

```bash
gnoban -f '(ua "Knots" or srv 26) and not srv 29'
```

Unban nodes that no longer meet the criteria:

```bash
gnoban -u 'Knots' --unban
```

For a full list of options, run:

```bash
gnoban --help
```

## Configuration file examples

Instead of passing arguments on every run, you can define them in `gnoban.toml`. By default, GNOBAN looks for this file in the same directory as the script. Use `-conf` to point to an alternative path:

```bash
gnoban -conf /etc/gnoban/gnoban.toml
```

Example `gnoban.toml` to ban nodes running Bitcoin Knots or using v1 transport, with unbanning enabled:

```toml
unban = true
useragent = ["Knots"]
transport = "v1"
```

Example using a complex filter expression:

```toml
filterexpr = "(ua 'Knots' or srv 26) and not srv 29"
```

See [`gnoban.toml.example`](../gnoban.toml.example) for a full reference of all available options.
