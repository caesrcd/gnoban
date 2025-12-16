#!/usr/bin/python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 CaesarCoder <caesrcd@tutamail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/licenses/mit-license.php.
"""
GNOBAN - A program to analyze and ban Bitcoin nodes based on custom criteria.

This program evaluates known nodes on your local full node and the Bitnodes
Snapshot API. It supports filtering by minimum fee rate, service flags, user
agent, and protocol version to ban remote nodes on your full node.

Author: CaesarCoder <caesrcd@tutamail.com>
License: MIT
"""

# Python module imports
import ast
import logging
import os
import re
import struct
import sys
import textwrap
import threading
from argparse import (
    ArgumentParser,
    RawDescriptionHelpFormatter,
    SUPPRESS
)
from base64 import b64decode
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from dataclasses import dataclass, field, fields
from datetime import datetime
from enum import Enum, StrEnum
from hashlib import sha256
from logging import Logger
from socket import AF_INET, AF_INET6
from time import sleep, time
from typing import Any, Dict, Set, Tuple
from zlib import decompress

# Third-party module imports
import requests
from bitcoin.messages import (
    MsgSerializable,
    msg_verack as BitcoinMsgvack,
    msg_version as BitcoinMsgver
)
from bitcoin.rpc import (
    JSONRPCError,
    Proxy as BitcoinRPCProxy
)
from socks import SOCKS5, socksocket

class Version:
    """Class responsible for managing program version information.

    Implements Semantic Versioning with automatic build hash generation.
    Build hash is calculated from source file SHA256 in development mode.
    """
    MAJOR = 1
    MINOR = 0
    PATCH = 1

    @classmethod
    def get_build_hash(cls) -> str | None:
        """Generates SHA256 hash of the source file for version tracking.

        Returns the first 8 characters of the hash, or None when the file
        cannot be read (e.g., when running from a packaged executable).
        """
        sha256_hash = sha256()
        try:
            with open(__file__, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()[:8]
        except FileNotFoundError:
            return None

    @classmethod
    def get_full_version(cls) -> str:
        """Returns complete version string in SemVer format.

        Appends build hash when running from source code.
        Format: MAJOR.MINOR.PATCH+build.HASH (e.g., 1.0.1+build.a1b2c3d4)
        """
        version = f'{cls.MAJOR}.{cls.MINOR}.{cls.PATCH}'

        build = cls.get_build_hash()
        if build:
            version += f'+build.{build}'

        return version

__version__ = Version.get_full_version()

class Color(StrEnum):
    """ANSI color codes used for formatting terminal output.

    Each member represents a specific color or reset code following
    the ANSI escape sequence format (\033[<code>m).
    Typically used to enhance the visibility of status messages.
    """
    RST   = '\033[0m'   # Reset
    CYN   = '\033[36m'  # Cyan
    GRN_L = '\033[92m'  # Green Light
    RED_L = '\033[91m'  # Red Light
    WHT_L = '\033[97m'  # White Light

class Status(Enum):
    """Enumeration representing possible statuses for banner messages.

    Each status consists of a color code and a human-readable label.
    Intended for visual output formatting in terminal environments.
    """
    EMPTY  = (Color.RST,   '      ')
    OK     = (Color.GRN_L, '  OK  ')
    FAILED = (Color.RED_L, 'FAILED')

    @property
    def color(self) -> str:
        """Returns the ANSI color code associated with the status."""
        return self.value[0]

    @property
    def label(self) -> str:
        """Returns the text label associated with the status."""
        return self.value[1]

@dataclass
class DefaultOptions:
    """Configuration options for ban management.

    Attributes:
        bantime: Time in seconds how long the node is banned.
        max_attempts: Max failed attempts before unbanning inactive nodes.
        unban: Enable unbanning of nodes that do not meet the criteria.

    Raises:
        ValueError: If validation fails for bantime or max_attempts.
    """
    bantime: int = 31536000
    max_attempts: int = 3
    unban: bool = False

    def __setattr__(self, name: str, value: Any) -> None:
        """Validates attribute constraints before assignment."""
        msg_pre = f'argument -{name}'
        if name == 'bantime' and value < 1:
            raise ValueError(f"{msg_pre}: value must be at least 1: '{value}'")
        if name == 'max_attempts' and value < 1:
            raise ValueError(f"{msg_pre}: value must be at least 1: '{value}'")
        super().__setattr__(name, value)

opts = DefaultOptions()

@dataclass
class Filter:
    """Criteria used to filter nodes based on specific attributes.

    Each attribute has a default value. Empty/zero values mean the filter is not applied.

    Attributes:
        filter_expr: A filter expression (logical string condition).
        minfeefilter: Minimum fee rate (in BTC/kvB) to match.
        service: Set of service flags to match.
        useragent: Set of user agent strings to match.
        version: Set of protocol versions to match.
    """
    filter_expr: str = ''
    minfeefilter: float = 0
    service: Set[int] = field(default_factory=set)
    useragent: Set[str] = field(default_factory=set)
    version: Set[int] = field(default_factory=set)

    def is_empty(self) -> bool:
        """Check if no filter criteria is set.

        Returns:
            True if all filter attributes are empty/falsy, False otherwise.
        """
        return not any(self.__dict__.values())

criteria = Filter()

@dataclass
class Node:
    """Represents a remote node with network connection metadata.

    Attributes:
        addr: IP address and port of the node.
        network: Network type (e.g., ipv4, ipv6, onion).
        attempts: Total number of unsuccessful connection attempts.
        conntime: Unix timestamp when the connection was established.
        services: Service flags advertised by the node.
        version: Protocol version used by the node.
        subver: User agent string of the node.
        minfeefilter: Minimum fee rate of the node (in BTC/kvB).
    """
    addr: str
    network: str
    attempts: int = 0
    services: int = 0
    conntime: int = 0
    version: int = 0
    subver: str = ''
    minfeefilter: float = 0

    def is_empty(self) -> bool:
        """Returns whether the node lacks ALL relevant metadata.

        Returns:
            True only if conntime, services, version, and subver are all empty/zero.
        """
        # Note: addr, network, attempts, and minfeefilter are not checked
        return not (self.conntime or self.services or self.version or self.subver)

allnodes: Dict[str, Node] = {}

class Proxy:
    """Global proxy configuration settings (static class).

    Class Attributes:
        ip: IP address of the proxy server.
        port: Port number of the proxy server.
        url: Dictionary containing protocol-to-proxy URL mappings.
    """
    ip: str | None = None
    port: int | None = None
    url: Dict[str, str] | None = None

    @classmethod
    def set(cls, proxy: str) -> None:
        """Set global proxy configuration.

        Parses proxy address and creates socks5h:// URLs for HTTP/HTTPS.
        If port is omitted, uses DEFAULT_TOR_SOCKS_PORT as fallback.

        Args:
            proxy: Proxy address in format 'ip:port' or just 'ip'
        """
        cls.ip, cls.port = split_addressport(proxy, DEFAULT_TOR_SOCKS_PORT)
        cls.url = {
            'http': f'socks5h://{cls.ip}:{cls.port}',
            'https': f'socks5h://{cls.ip}:{cls.port}'
        }

    @classmethod
    def is_set(cls) -> bool:
        """Check if a proxy is currently configured.

        Returns:
            True if the proxy IP is set, False otherwise.
        """
        return cls.ip is not None

class SocketFactory:
    """Socket factory for different network types.

    Creates and configures sockets for various network types (ipv4, ipv6,
    onion, i2p, cjdns) with appropriate proxy settings and 10s timeout.
    Provides reliable socket read operations with EOF detection.
    """

    @staticmethod
    def create_socket(network: str) -> socksocket:
        """Create and configure a socket for the specified network type.

        Args:
            network: Network type (ipv4, ipv6, onion, i2p, and cjdns)

        Returns:
            Configured socket with appropriate proxy settings (if needed)
                and default timeout applied
        """
        if network == 'i2p':
            sock = socksocket(AF_INET)
            sock.set_proxy(SOCKS5, '127.0.0.1', DEFAULT_I2P_SOCKS_PORT)
        elif network == 'cjdns':
            sock = socksocket(AF_INET6)
        elif Proxy.is_set():
            sock = socksocket(AF_INET)
            sock.set_proxy(SOCKS5, Proxy.ip, Proxy.port)
        elif network == 'onion':
            sock = socksocket(AF_INET)
            sock.set_proxy(SOCKS5, '127.0.0.1', DEFAULT_TOR_SOCKS_PORT)
        else:
            family = AF_INET6 if network == 'ipv6' else AF_INET
            sock = socksocket(family)

        sock.settimeout(10)
        return sock

    @staticmethod
    def read_bytes(sock: socksocket, length: int) -> bytes:
        """Read exactly the specified number of bytes from the socket.

        Args:
            sock: Socket to read data from
            length: Exact number of bytes to read

        Returns:
            Buffer containing exactly 'length' bytes received

        Raises:
            EOFError: If socket closes before all bytes are received.
        """
        recvbuf = b''
        while len(recvbuf) < length:
            chunk = sock.recv(length - len(recvbuf))
            if not chunk:
                raise EOFError()
            recvbuf += chunk
        return recvbuf

@dataclass
class ThreadState:
    """Manages the lifecycle state of a background thread.

    Attributes:
        lock: Threading lock used for synchronization.
        thread: Reference to the running thread instance.
        started_at: Unix timestamp (seconds) when the thread started.
        finished_at: Unix timestamp (seconds) when the thread finished.
    """
    lock: threading.Lock = field(default_factory=threading.Lock)
    thread: threading.Thread | None = None
    started_at: float = 0
    finished_at: float = 0

    def should_wait(self) -> bool:
        """Checks if the thread is still in its waiting period.

        Waiting periods:
          - No wait on first run (finished_at == 0)
          - 900 seconds (15 min) after successful run with nodes (duration > 10s)
          - 3600 seconds (1 hour) after run with no nodes (duration <= 10s)

        Returns:
            True if still waiting, False if ready to run.
        """
        if not self.finished_at:
            return False
        elapsed = time() - self.finished_at
        duration = self.finished_at - self.started_at
        wait_time = 900 if duration > 10 else 3600
        return elapsed < wait_time

threadctl = ThreadState()

DEFAULT_I2P_SOCKS_PORT: int = 4447  # Standard I2P SOCKS5 port
DEFAULT_TOR_SOCKS_PORT: int = 9050  # Standard Tor SOCKS5 port

# Set of banned node addresses (format: "ip:port")
listbanned: Set[str] = set()

# Module-level logger
logger: Logger = logging.getLogger(__name__)

# Configuration for Bitcoin RPC connection via bitcoin.rpc.Proxy
rpc_conf: dict[str, Any] = {
    'service_url': None,    # RPC endpoint URL
    'btc_conf_file': None,  # Path to bitcoin.conf
    'timeout': 30           # Request timeout (seconds)
}

def banner() -> None:
    """Prints a stylized ASCII banner to standard output.

    The banner is stored as a base64-encoded, zlib-compressed byte string.
    Upon decoding and decompression, the resulting ASCII art is printed.
    """
    banner_encoded = (
        b'eJxtkEELwjAMhe/9C7s8PLiLrIIgeJJNRQ9lgh5XyIYTvNQdFMR/b5JtdAcL4bX5XhI'
        b'a4N9JqtU6EJn43qzD0Z2L3KE87w/KAevhB3g95JfdCXMUealUaom0mqJKgaeYwAgMbE'
        b'qoPQtUYTldiz9VFT6oGowMdxx2Ek77x7zzmacRmnG06Bh8hNFiULJZhN5wJTu0HfM+2'
        b'ANM1U6glX/bvq9cebz6hq0GXdasaFo8u/b+2qLs3uieCF98mvftkc2SahnMD9ZJZcI='
    )
    sys.stdout.write(decompress(b64decode(banner_encoded)).decode())

def build_parser() -> ArgumentParser:
    """Builds and returns the command-line argument parser.

    Creates an ArgumentParser with two main argument groups:
      - Options: Program configuration (bantime, proxy, RPC connection, etc.)
      - Criteria: Node filtering rules (expressions, minfeefilter, services, etc.)

    Supports complex filter expressions with logical operators (and, or, not)
    and comparison operators for protocol versions.

    Returns:
        Configured parser ready to parse command-line arguments.
    """
    parser = ArgumentParser(
        add_help=False,
        usage='%(prog)s [options]... [criteria]...',
        description=(
            'Scan and evaluate known nodes to determine which should be banned '
            'based on specified criteria.'
        ),
        epilog=textwrap.dedent('''\
            Complex filter expressions can be built using the keywords `and`, `or`, and `not`
            to combine primitives. You may also use `&&`, `||`, and `!` as shorthand for these.

            Valid primitives:
              mff <num>              Match if minfeefilter is greater than <num> (BTC/kvB).
              ver <num>              Match node protocol version.
              ver >= <num>           Match version with comparison operator.
              ua 'pattern'           Match substring in user agent.
              srv <num>              Match if service flag is present.

            Examples:
              %(prog)s -f '(ua "Knots" or srv 26) and not srv 29'
              %(prog)s -conf /mnt/btc/bitcoin.conf --unban -m 0.000009
              %(prog)s -rpcurl http://user:pass@192.168.0.10:8332 -s 27

            Note:
              When using simple filters (-m, -s, -u, -v) alongside -f, nodes matching *any* of the conditions will be selected.
            '''),
        formatter_class=RawDescriptionHelpFormatter
    )
    parser.add_argument('-h', '--help', action='help', help=SUPPRESS)
    argrp_opt = parser.add_argument_group('Options')
    argrp_opt.add_argument('-bantime', metavar='num', type=int,
        default=opts.bantime, help=(
            'Time in seconds how long the node is banned. '
            f'(default: {opts.bantime})'
        )
    )
    argrp_opt.add_argument('-conf', metavar="'str'", type=str,
        help='Specify the Bitcoin node configuration file.')
    argrp_opt.add_argument('-max-attempts', metavar='num', type=int,
        default=opts.max_attempts, help=(
            'Max failed attempts before unbanning inactive nodes. '
            f'(default: {opts.max_attempts})'
        )
    )
    argrp_opt.add_argument('-proxy', metavar='ip[:port]', type=str,
        help='Connect through SOCKS5 proxy.')
    argrp_opt.add_argument('-rpcurl', metavar="'str'", type=str,
        help='Specify the Bitcoin node RPC endpoint.')
    argrp_opt.add_argument('--unban', action='store_true',
        help='Enable unbanning of nodes that do not meet the criteria.')
    argrp_opt.add_argument('--version', action='version',
        version=textwrap.dedent(f'''
            %(prog)s (GNOBAN) v{__version__}
            Copyright (C) 2025 CaesarCoder <caesrcd@tutamail.com>
            Distributed under the MIT software license, see the accompanying
            file COPYING or https://opensource.org/licenses/mit-license.php.
            '''),
        help='Show version information.')
    argrp_cri = parser.add_argument_group('Criteria')
    argrp_cri.add_argument('-f', '--filter', metavar="'expr'", type=str,
        help='Filter nodes using logical expressions.')
    argrp_cri.add_argument('-m', dest='minfeefilter', metavar='num', type=float,
        help='Match if minfeefilter is greater than <num> (BTC/kvB).')
    argrp_cri.add_argument('-s', dest='service', metavar='num', type=int, nargs='+',
        help='Service flags provided by the node.')
    argrp_cri.add_argument('-u', dest='useragent', metavar="'str'", type=str, nargs='+',
        help="Matches part of the node's user agent.")
    argrp_cri.add_argument('-v', dest='version', metavar='num', type=int, nargs='+',
        help='Protocol version of the node.')

    return parser

def check_bitcoind() -> None:
    """Verifies connectivity with the bitcoin node using RPC.

    Executes the 'uptime' command through the RPC interface to ensure the node is reachable.
    Displays a status message based on the result, and exits if the check fails due to
    connection or permission errors.
    """
    mark(Status.EMPTY, 'Checking access to bitcoin node via RPC...')

    try:
        BitcoinRPCProxy(**rpc_conf).call('uptime')
    except JSONRPCError as e:
        mark(Status.FAILED, f"{e.args[0].get('message')}\r\n")
        sys.exit(1)
    except Exception as e:  # pylint: disable=broad-exception-caught
        mark(Status.FAILED, f'{e}\r\n')
        sys.exit(1)

    mark(Status.OK, f"Checked access to bitcoin node via RPC.{' ' * 5}")

def compile_node_filter(expr: str) -> str:
    """Translates a simplified filter expression string into a valid Python expression.

    This function allows users to write human-friendly filter conditions using keywords
    like 'mff', 'srv', 'ua', and 'ver', along with basic boolean operators.

    Supported transformations:
      - &&, ||, !       → and, or, not
      - mff N           → node.minfeefilter > N
      - srv N           → (node.services & (1 << N))
      - ua 'pattern'    → re.search(r'pattern', node.subver)
      - ver N           → node.version == N
      - ver >= N        → node.version >= N

    Args:
        expr: A user-provided filter string.

    Returns:
        A valid Python expression string suitable for eval().

    Note:
        The returned string is intended to be used with eval().
        Always ensure that 'node' and 're' are properly scoped and trusted.
    """

    # Convert logical operators to Python syntax
    expr = re.sub(r'\s*&&\s*', ' and ', expr)
    expr = re.sub(r'\s*\|\|\s*', ' or ', expr)
    expr = re.sub(r'(?<!\w)!(?!=)', 'not ', expr)  # ! → not (but preserve != operator)

    # Convert filter primitives to Python expressions
    expr = re.sub(r'\bmff\s+([\d.]+)', r'node.minfeefilter > \1', expr)
    expr = re.sub(r'\bsrv\s+(\d+)', r'(node.services & (1 << \1))', expr)
    expr = re.sub(r'\bua\s+[\'"](.+?)[\'"]', r"re.search(r'\1', node.subver)", expr)
    expr = re.sub(r'\bver\s+(\d+)', r'node.version == \1', expr)
    expr = re.sub(r'\bver\s*([=!<>]+)\s*(\d+)', r'node.version \1 \2', expr)

    return expr

def exec_getpeerinfo() -> None:
    """Retrieves and processes the current peer information from bitcoind.

    Fetches peer data via the 'getpeerinfo' RPC command, parses the JSON output,
    and updates the internal node list accordingly. Filters out nodes based on
    network visibility and ban list criteria. Attempts to disconnect banned or
    mismatched nodes by invoking the 'disconnectnode' RPC command.
    """
    try:
        rpc_proxy = BitcoinRPCProxy(**rpc_conf)
        peerinfo = rpc_proxy.call('getpeerinfo')
    except JSONRPCError as e:
        mark(Status.FAILED,
            'Could not load peers info. '
            f"[{e.args[0].get('message')}]", False)
        return
    except Exception as e:  # pylint: disable=broad-exception-caught
        mark(Status.FAILED, f'Could not load peers info. [{e}]', False)
        return

    for peer in peerinfo:
        conntime = peer.get('conntime')
        network = peer.get('network')
        version = peer.get('version')
        if int(time()) - conntime <= 15 or not version or network == 'not_publicly_routable':
            continue

        node = Node(
            addr=peer.get('addr'),
            network=network,
            services=int(peer.get('services'), 16),
            conntime=conntime,
            version=version,
            subver=peer.get('subver'),
            minfeefilter=float(peer.get('minfeefilter'))
        )

        address, _ = split_addressport(node.addr)
        node_old = allnodes.get(address)
        if address != '127.0.0.1' and (not node_old or conntime != node_old.conntime):
            allnodes[address] = node
        if address == '127.0.0.1' or node_old:
            if not match_node(node) or (address != '127.0.0.1' and address not in listbanned):
                continue
            try:
                rpc_proxy.call('disconnectnode', node.addr)
                stamp(f'Node disconnected: net={node.network}, services={node.services}, '
                    f'version={str(node.version)}{node.subver}')
            except JSONRPCError as e:
                if e.args[0].get('code') != -29:
                    mark(Status.FAILED,
                        f'Could not disconnect address {node.addr} '
                        f'({str(node.version)}{node.subver}) '
                        f"[{e.args[0].get('message')}]", False)
            except Exception as e:  # pylint: disable=broad-exception-caught
                mark(Status.FAILED,
                    f'Could not disconnect address {node.addr} '
                    f'({str(node.version)}{node.subver}) '
                    f'[{e}]', False)
            continue

def exec_setban(only_recents: bool) -> None:
    """Bans or unbans nodes based on filtering criteria and connection status.

    Iterates over known nodes and:
      - Bans nodes matching filter criteria (not already banned)
      - Unbans nodes not matching criteria (if --unban is enabled)
      - Unbans inactive nodes after max failed connection attempts

    Args:
        only_recents: If True, only processes nodes connected within the last 5 minutes.
    """
    now = time()
    try:
        rpc_proxy = BitcoinRPCProxy(**rpc_conf)
    except Exception:  # pylint: disable=broad-exception-caught
        return

    for address, node in allnodes.items():
        if node.attempts >= opts.max_attempts and address in listbanned:
            action, op = 'remove', None
            msg = (
                'Node inactive: The address was unbanned after '
                f'{node.attempts} failed connection attempts'
            )
        elif node.is_empty() or (only_recents and node.conntime < now - 300):
            continue
        else:
            msg = (
                f'Node: net={node.network}, services={node.services}, '
                f'version={str(node.version)}{node.subver}'
            )
            is_match = match_node(node)

            if is_match and address not in listbanned:
                action, op = ('add', opts.bantime), 'banned'
            elif opts.unban and not is_match and address in listbanned:
                action, op = 'remove', 'unbanned'
            else:
                continue

        try:
            rpc_proxy.call('setban', address, *([action] if isinstance(action, str) else action))
            (listbanned.discard if action == 'remove' else listbanned.add)(address)
            stamp(msg if op is None else msg.replace('Node:', f'Node {op}:', 1))
        except JSONRPCError as e:
            msg = f'Unable to send the setban request to {address}'
            if e.args[0].get('code') == -23:
                stamp(f'{msg} (already banned)')
            elif e.args[0].get('code') == -30:
                stamp(f'{msg} (already unbanned)')
            else:
                mark(Status.FAILED, f"{msg} [{e.args[0].get('message')}]", False)
        except Exception as e:  # pylint: disable=broad-exception-caught
            msg = f'Unable to send the setban request to {address}'
            mark(Status.FAILED, f'{msg} [{e}]', False)

def getdata_node(node: Node) -> Node:
    """Attempts to connect to a node and retrieve its version information.

    Sends a Bitcoin protocol 'version' message and waits for the response
    to extract version, services, subver, and feefilter data.

    Args:
        node: Node object containing address and network info.

    Returns:
        Updated node with version info on success, or unchanged node on failure.
        Connection errors are silently ignored.
    """
    sock = SocketFactory.create_socket(node.network)

    try:
        address, port = split_addressport(node.addr)
        sock.connect((address, port))
        msg_version = BitcoinMsgver()
        msg_version.nVersion = 70016
        msg_version.fRelay = False
        sock.send(msg_version.to_bytes())

        while True:
            header = SocketFactory.read_bytes(sock, 24)
            length = struct.unpack('<I', header[16:20])[0]
            payload = SocketFactory.read_bytes(sock, length)
            match header[4:16].rstrip(b'\x00'):
                case b'version':
                    msg_version = MsgSerializable.from_bytes(header + payload)
                    node.conntime = int(time())
                    node.version = int(msg_version.nVersion)
                    node.services = int(msg_version.nServices)
                    node.subver = msg_version.strSubVer.decode('utf-8', errors='ignore')
                    sock.send(BitcoinMsgvack().to_bytes())
                case b'feefilter':
                    node.minfeefilter = float(struct.unpack('<Q', payload)[0]) / 100000000
                    break
    except Exception:  # pylint: disable=broad-exception-caught
        # Silently fail - node returned with empty/unchanged metadata
        pass

    sock.close()
    return node

def load_allnodes() -> None:
    """Loads all known Bitcoin network node addresses into the global registry.

    Fetches node addresses via 'getnodeaddresses' RPC (count=0 for all nodes)
    and populates allnodes dictionary with Node instances keyed by IP address.
    Skips duplicate addresses and formats IPv6/CJDNS with brackets per RFC 3986.
    """
    mark(Status.EMPTY, 'Loading known addresses...')

    try:
        nodeaddresses = BitcoinRPCProxy(
            **(rpc_conf | {'timeout': 300})
        ).call('getnodeaddresses', 0)
    except JSONRPCError as e:
        mark(Status.FAILED, f"{e.args[0].get('message')}\r\n")
        sys.exit(1)
    except Exception as e:  # pylint: disable=broad-exception-caught
        mark(Status.FAILED, f'{e}\r\n')
        sys.exit(1)

    address_count = 0
    for node in nodeaddresses:
        if allnodes.get(node['address']):
            continue
        if node['network'] in {'ipv6', 'cjdns'}:
            addr = f"[{node['address']}]:{node['port']}"
        else:
            addr = f"{node['address']}:{node['port']}"
        allnodes[node['address']] = Node(
            addr=addr,
            network=node['network']
        )
        address_count += 1

    mark(Status.OK, f'Loaded known addresses ({address_count} entries).')

def load_listbanned() -> None:
    """Loads banned node addresses into the global listbanned set.

    Fetches banned addresses via 'listbanned' RPC and updates the global set.
    If --unban is enabled, creates placeholder Node entries for banned addresses
    not in the allnodes registry (needed for later unban evaluation).
    """
    mark(Status.EMPTY, 'Loading banned addresses...')

    try:
        bannedaddresses = BitcoinRPCProxy(**rpc_conf).call('listbanned')
    except JSONRPCError as e:
        mark(Status.FAILED, f"{e.args[0].get('message')}\r\n")
        sys.exit(1)
    except Exception as e:  # pylint: disable=broad-exception-caught
        mark(Status.FAILED, f'{e}\r\n')
        sys.exit(1)

    listbanned.clear()
    for node in bannedaddresses:
        address = node['address'].split('/')[0]
        listbanned.add(address)

        if not opts.unban or allnodes.get(address):
            continue

        if address.endswith('.onion'):
            network = 'onion'
        elif address.endswith('.b32.i2p'):
            network = 'i2p'
        elif ':' in address:
            network = 'cjdns' if address.startswith('fc') else 'ipv6'
        else:
            network = 'ipv4'

        port = 0 if network == 'i2p' else 8333
        addr = f'[{address}]:{port}' if ':' in address else f'{address}:{port}'
        allnodes[address] = Node(
            addr=addr,
            network=network
        )

    mark(Status.OK, f'Loaded banned addresses ({len(listbanned)} entries).')

def main() -> None:
    """Entry point that parses CLI arguments, validates filters, and starts processing.

    Parses command-line arguments, validates filtering criteria (regex patterns,
    filter expressions), configures proxy settings, and calls start() if criteria
    are valid. Prints help and exits if no criteria specified or validation fails.
    """
    parser = build_parser()
    args = parser.parse_args()

    # Copy parsed arguments to DefaultOptions instance (validates constraints)
    try:
        for f in fields(DefaultOptions):
            if hasattr(args, f.name):
                setattr(opts, f.name, getattr(args, f.name))
    except ValueError as e:
        parser.error(e)

    # Validate user agent regex patterns
    if args.useragent:
        try:
            for pattern in args.useragent:
                re.compile(pattern)
            criteria.useragent = set(args.useragent)
        except re.error as e:
            parser.error(f'argument -u: invalid regex: {e}')

    # Validate filter expression via AST parsing and test evaluation
    if args.filter:
        parsed_expr = compile_node_filter(args.filter)
        try:
            ast.parse(parsed_expr, mode='eval')
            criteria.filter_expr = parsed_expr
            node_test = Node(addr='', network='')
            # pylint: disable=eval-used
            eval(criteria.filter_expr, {}, {'node': node_test, 're': re})
        except Exception as e:  # pylint: disable=broad-exception-caught
            msg = getattr(e, 'msg', str(e))
            parser.error(f'argument -f: invalid filter expression: {msg}')

    # Set filtering criteria
    criteria.minfeefilter = args.minfeefilter or 0
    criteria.service = set(args.service or [])
    criteria.version = set(args.version or [])

    # Configure RPC connection
    rpc_conf['service_url'] = args.rpcurl
    rpc_conf['btc_conf_file'] = args.conf

    # Configure proxy if provided
    if args.proxy:
        Proxy.set(args.proxy)

    # Start processing if criteria are specified
    if criteria.is_empty():
        parser.print_help()
    else:
        start()

def mark(status: Color | Status, text: str, answer: bool=True) -> None:
    """Displays a colored status label and message, then logs it.

    Prints formatted message with ANSI color codes to stdout and logs to
    the module logger (ERROR level for FAILED status, INFO for others).

    Args:
        status: Status enum (with label and color) or Color enum (color only).
        text: Message text to display and log.
        answer: If True, overwrites current line for progress updates;
                if False, prints on new line.
    """
    color = status.color if isinstance(status, Status) else Status.EMPTY.color
    label = status.label if isinstance(status, Status) else Status.EMPTY.label

    prefix = '\r' if answer and status != Status.EMPTY else '\n'
    suffix = '\r\n' if answer and status == Status.FAILED else ' '
    msg = f'{prefix}{Color.WHT_L}[{color}{label}{Color.WHT_L}]{Color.RST}{suffix}{text}'

    sys.stdout.write(msg)
    sys.stdout.flush()

    if status == Status.FAILED:
        logger.error(text)
    else:
        logger.info(text)

def match_node(node: Node) -> bool:
    """Checks if a node matches any of the defined filter criteria.

    Uses OR logic: returns True if node matches ANY criterion.
    Empty criteria fields are ignored.

    Args:
        node: Network node to evaluate.

    Returns:
        True if node matches at least one criterion, False otherwise.
    """
    if criteria.minfeefilter and node.minfeefilter > criteria.minfeefilter:
        return True

    if criteria.version and node.version in criteria.version:
        return True

    if criteria.useragent and any(re.search(p, node.subver) for p in criteria.useragent):
        return True

    if criteria.service and any(node.services & (1 << s) for s in criteria.service):
        return True

    if criteria.filter_expr:
        # pylint: disable=eval-used
        if eval(criteria.filter_expr, {}, {'node': node, 're': re}):
            return True

    return False

def probe_nodes() -> None:
    """Probes nodes without metadata to retrieve version information.

    Uses thread pool (16 workers) to concurrently connect to nodes.
    Processes in batches of 100 to control memory usage.

    Updates node metadata on success, increments attempts on failure.
    Thread-safe updates to global allnodes registry.
    """
    threadctl.started_at = time()
    nodes_snapshot = list(allnodes.values())

    if not nodes_snapshot:
        stamp('No nodes found. Probe nodes thread paused for 1 hour')
        threadctl.finished_at = time()
        return

    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = set()
        nodes_to_process = iter(nodes_snapshot)

        def submit_batch() -> None:
            for node in nodes_to_process:
                node = Node(
                    addr=node.addr,
                    network=node.network,
                    attempts=node.attempts
                )
                futures.add(executor.submit(getdata_node, node))
                if len(futures) >= 100:
                    break

        submit_batch()
        while futures:
            done, futures = wait(futures, return_when=FIRST_COMPLETED)
            for future in done:
                node = future.result()
                node.attempts = node.attempts + 1 if node.is_empty() else 0
                address, _ = split_addressport(node.addr)
                allnodes[address] = node
            submit_batch()

    stamp('Probe nodes thread paused for 15 minutes')
    threadctl.finished_at = time()

def snapshot_bitnodes() -> None:
    """Downloads the latest node snapshot from Bitnodes API.

    Fetches active node addresses from Bitnodes public API and adds any
    missing nodes to the global allnodes registry. Skips nodes already present.
    Uses proxy settings if configured.
    """
    mark(Status.EMPTY, 'Downloading latest snapshot from Bitnodes...')

    try:
        response = requests.get(
            'https://bitnodes.io/api/v1/snapshots/latest/',
            proxies=Proxy.url,
            timeout=30)
        response.raise_for_status()
        data = response.json()
        nodeaddresses = data.get('nodes', {})
    except requests.RequestException as e:
        mark(Status.FAILED, e)
        return

    address_count = 0
    for addressport in nodeaddresses:
        address, _ = split_addressport(addressport)
        if allnodes.get(address):
            continue

        if address.endswith('.onion'):
            network = 'onion'
        elif ':' in address:
            network = 'ipv6'
        else:
            network = 'ipv4'

        allnodes[address] = Node(
            addr=addressport,
            network=network
        )
        address_count += 1

    mark(Status.OK, f'Downloaded latest snapshot from Bitnodes ({address_count} entries).')

def split_addressport(addressport: str, dport: int=8333) -> Tuple[str, int]:
    """Splits an address string into (address, port).

    Handles IPv4, IPv6 (with brackets), and addresses without explicit port.

    Args:
        addressport: Address string, optionally with port (e.g., '1.2.3.4:8333', '[::1]:8333').
        dport: Default port if none specified (default: 8333).

    Returns:
        Tuple of (address, port).

    Raises:
        ValueError: If IPv6 address format is malformed.
    """
    if addressport.startswith('['):
        match = re.match(r'^\[([^\]]+)\](?::(\d+))?$', addressport)
        if not match:
            raise ValueError(f'Malformed IPv6 address: {addressport}')
        address = match.group(1)
        port = int(match.group(2)) if match.group(2) else dport
    else:
        parts = addressport.rsplit(':', 1)
        if len(parts) == 2 and parts[1].isdigit():
            address, port = parts[0], int(parts[1])
        else:
            address, port = addressport, dport
    return address, port

def stamp(text: str) -> None:
    """Prints a timestamped log message with color formatting and logs it.

    Outputs message to stdout with ISO 8601 timestamp in cyan.
    Falls back to stderr if stdout fails (e.g., broken pipe).
    Also logs message via module logger at INFO level.

    Args:
        text: Log message to display and log.
    """
    date = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
    try:
        sys.stdout.write(f'\r\n{Color.CYN}{date}{Color.RST} {text}')
        sys.stdout.flush()
    except (BrokenPipeError, ValueError):
        try:
            sys.stdout.close()
        except Exception:  # pylint: disable=broad-exception-caught
            pass
        sys.stderr.write(f'\r\n{Color.CYN}{date}{Color.RST} {text}')
        sys.stderr.flush()
    logger.info(text)

def start() -> None:
    """Initializes and starts the main monitoring loop.

    Configures logging to debug.log, loads initial data, and enters monitoring
    loop with 10-second intervals. Spawns background probe thread when ready.
    Handles KeyboardInterrupt for graceful shutdown.
    """
    banner()

    # Configure file logging (INFO level, append mode, ISO 8601 timestamps)
    logger.setLevel(logging.INFO)
    file_handler = logging.FileHandler('debug.log', mode='a', encoding='utf-8')
    file_handler.setFormatter(logging.Formatter(
        fmt='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S'
    ))
    logger.addHandler(file_handler)
    logger.info('GNOBAN version v%s', __version__)

    try:
        check_bitcoind()
        while True:
            # Check if probe thread needs to start
            with threadctl.lock:
                thread_dead = threadctl.thread is None or not threadctl.thread.is_alive()
                should_start = thread_dead and not threadctl.should_wait()

            if should_start:
                # Reload data and start probe thread
                load_listbanned()
                load_allnodes()
                snapshot_bitnodes()

                msg = 'started' if threadctl.thread is None else 'resumed'
                stamp(f'Probe nodes thread {msg}')

                with threadctl.lock:
                    threadctl.thread = threading.Thread(target=probe_nodes)
                    threadctl.thread.start()

                only_recents = False
            else:
                only_recents = True

            # Process peers and manage bans
            exec_getpeerinfo()
            exec_setban(only_recents)
            sleep(10)
    except KeyboardInterrupt:
        stamp('Shutdown: done\r\n')
        os._exit(0)

if __name__ == '__main__':
    main()
