# GNOBAN - Global Node Search & Ban

A script to analyze and ban Bitcoin nodes based on custom criteria.

## 📋 Description

**GNOBAN** evaluates Bitcoin nodes connected to your full node and automatically bans those that match specified criteria — such as service flags, protocol versions, or user agent strings.

## 📌 Features

- Scans all known addresses stored in your node's `addrman`
- Automatically bans nodes according to defined criteria:
  - Protocol version
  - User agent substring match
  - Service flags
- SOCKS5 proxy support

## 📦 Requirements

- Python 3.11+
- `bitcoind` running with RPC enabled (`server=1`)
- Access to `bitcoin-cli`

## 💻 Usage

```bash
git clone https://github.com/caesrcd/gnoban.git
cd gnoban
python -m venv myenv
source myenv/bin/activate
pip install -r requirements.txt
python gnoban.py --help
```

## 🔐 License

Distributed under the MIT software license, see the accompanying file COPYING or visit: https://opensource.org/licenses/mit.
