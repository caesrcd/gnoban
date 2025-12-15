# GNOBAN

[![Tests](https://github.com/caesrcd/gnoban/actions/workflows/tests.yml/badge.svg?event=push&label=Tests)](https://github.com/caesrcd/gnoban/actions/workflows/tests.yml)
[![Build](https://github.com/caesrcd/gnoban/actions/workflows/build.yml/badge.svg?event=push&label=Build)](https://github.com/caesrcd/gnoban/actions/workflows/build.yml)
[![Release](https://img.shields.io/github/v/release/caesrcd/gnoban?label=Release)](https://github.com/caesrcd/gnoban/releases)
![License](https://img.shields.io/github/license/caesrcd/gnoban?label=License)

A program to analyze and ban Bitcoin nodes based on custom criteria.

## Description

**GNOBAN** (Global Node Search & Ban) evaluates Bitcoin nodes connected to your node and bans those that match specified criteria — such as service flags, protocol versions, user agent strings, or minimum transaction fees.

## Features

- Scans all known addresses stored in your node's `addrman`
- Bans nodes according to defined criteria:
  - Minimum transaction fees
  - Protocol version
  - User agent substring match
  - Service flags
- Unbans nodes that no longer meet the criteria
- Unbans inactive addresses after multiple failed attempts
- Supports SOCKS5 proxy connections

## Requirements

- Bitcoin node running with RPC access allowed
- Python 3.11+ (only if running from source code)

## Verify your download

1. Go to the [releases](<https://github.com/caesrcd/gnoban/releases>) page to download the version for your platform.

2. Download the list of cryptographic checksums: **SHA256SUMS**

3. Download the signature file: **SHA256SUMS.asc**

4. Open a terminal (command prompt) and change the directory (`cd`) to your downloads folder.

5. Verify that the checksum of the downloaded file is listed in the checksum file using one of the following commands:

  - ***Linux***
    ```bash
    sha256sum --ignore-missing --check SHA256SUMS
    gnoban-1.0.0-x86_64-linux-gnu.tar.gz: OK
    ```

  - ***MacOS***
    ```bash
    shasum -a 256 --ignore-missing --check SHA256SUMS
    gnoban-1.0.0-x86_64-apple-darwin.zip: OK
    ```

  - ***Windows***
    ```bash
    certUtil -hashfile gnoban-1.0.0-win64.zip SHA256
    ```

    Ensure that the checksum produced by the command above matches one of the entries in the SHA256SUMS file. You can display the file contents with:

    ```bash
    type SHA256SUMS
    ```

6. If you haven’t already installed GNU Privacy Guard (GPG), [download it here](<https://gpg4win.org/download.html>) or see other [installation options](<https://www.gnupg.org/download/index.en.html#binary>).

7. To verify the signature, import the project’s public key and check that the checksum file was signed by a trusted key:

    ```bash
    gpg --keyserver hkps://keys.openpgp.org --recv-keys E2A0BF0D72D74483064D4FF9304952407A6E5C38
    gpg --verify SHA256SUMS.asc
    ```

## Usage

If you run GNOBAN on the same computer as your Bitcoin node, it will automatically detect the configuration file (`bitcoin.conf`) in the default directory.

If your configuration file is in a non-default location, specify the correct path using the `-conf` argument. For example:
```bash
gnoban -conf /path/the/bitcoin/bitcoin.conf ...
```

If you are running GNOBAN on another computer, you’ll need to specify the IP address and port of your Bitcoin node, along with the RPC username and password. For example:

```bash
gnoban -rpcurl http://username:password@192.168.0.10:8332 ...
```

For a full list of options, run:

```bash
gnoban --help
```

## License

Distributed under the MIT software license, see the accompanying file COPYING or visit: https://opensource.org/licenses/mit.
