# Global Node Search & Ban

A script to analyze and ban Bitcoin nodes based on custom criteria.

## Description

**GNOBAN** evaluates Bitcoin nodes connected to your node and bans those that match specified criteria — such as service flags, protocol versions, user agent strings, or minimum transaction fees.

## Features

- Scans all known addresses stored in your node's `addrman`
- Bans nodes according to defined criteria:
  - Minimum transaction fees
  - Protocol version
  - User agent substring match
  - Service flags
- Unbans nodes that no longer meet the criteria
- SOCKS5 proxy support

## Requirements

- Python 3.11+
- Bitcoin node running with RPC access allowed

## Usage

```bash
git clone https://github.com/caesrcd/gnoban.git
cd gnoban
python -m venv myenv
source myenv/bin/activate
pip install -r requirements.txt
python gnoban.py --help
```

## License

Distributed under the MIT software license, see the accompanying file COPYING or visit: https://opensource.org/licenses/mit.
