<div align="center">
  <h1>GNOBAN</h1>

  <img alt="Logo" src="https://github.com/caesrcd/gnoban/blob/master/share/logo.svg" width="200"/>

  <p>
    <strong>A program to analyze and ban Bitcoin nodes based on custom criteria.</strong>
  </p>

  <p>
    <a href="https://github.com/caesrcd/gnoban/actions/workflows/tests.yml">
      <img alt="Tests" src="https://github.com/caesrcd/gnoban/actions/workflows/tests.yml/badge.svg?event=push&label=Tests"/>
    </a>
    <a href="https://github.com/caesrcd/gnoban/actions/workflows/build.yml">
      <img alt="Build" src="https://github.com/caesrcd/gnoban/actions/workflows/build.yml/badge.svg?event=push&label=Build"/>
    </a>
    <a href="https://github.com/caesrcd/gnoban/releases">
      <img alt="Release" src="https://img.shields.io/github/v/release/caesrcd/gnoban?label=Release"/>
    </a>
  </p>
</div>

**GNOBAN** (Global Node Search & Ban) evaluates Bitcoin nodes connected to your node and bans those that match specified criteria — such as service flags, protocol versions, user agent strings, or minimum transaction fees.

## Requirements

- Bitcoin node running with RPC access allowed
- Python 3.11+ (only if running from source)

## How to use

- [Installation from source](doc/install.md)
- [Pre-built binaries](doc/binaries.md)
- [Usage](doc/usage.md)

## Features

- Scans all known addresses stored in your node's `addrman`
- Bans nodes according to defined criteria:
  - Minimum transaction fees
  - Protocol version
  - User agent substring match
  - Service flags
  - Transport protocol type (v1/v2)
- Unbans nodes that no longer meet the criteria
- Unbans inactive addresses after multiple failed attempts
- Supports SOCKS5 proxy connections

## License

Distributed under the MIT software license, see the accompanying file COPYING or visit: https://opensource.org/licenses/mit.
