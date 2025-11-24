#!/usr/bin/python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 CaesarCoder <caesrcd@tutamail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/licenses/mit-license.php.
"""
GNOBAN - A script to analyze and ban Bitcoin nodes based on custom criteria.

This script evaluates known nodes on your local full node and the Bitnodes Snapshot API.
It supports filtering by minimum fee rate, service flags, user agent, and protocol version
to ban remote nodes on your full node.

Author: CaesarCoder <caesrcd@tutamail.com>
License: MIT
"""

# Python module imports
import ast
import logging
import os
import re
import socket
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
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, StrEnum
from logging import Logger
from time import time, sleep
from typing import Dict, List, Optional, Tuple, Union
from zlib import decompress

# Third-party module imports
import requests
from bitcoin.messages import (
    msg_version as BitcoinMsgver,
    msg_verack as BitcoinMsgvack,
    MsgSerializable
)
from bitcoin.rpc import (
    JSONRPCError,
    Proxy as BitcoinRPCProxy
)
from socks import socksocket, SOCKS5

# Current program version (Semantic Versioning)
__version__ = '1.0.0'

class Color(StrEnum):
    """
    ANSI color codes used for formatting terminal output.

    Each member represents a specific color or reset code,
    typically used to enhance the visibility of status messages.
    """
    RST   = '\033[0m'   # Reset
    CYN   = '\033[36m'  # Cyan
    GRN_L = '\033[92m'  # Green Light
    RED_L = '\033[91m'  # Red Light
    WHT_L = '\033[97m'  # White Light

class Status(Enum):
    """
    Enumeration representing possible statuses for banner messages.

    Each status consists of a color code and a human-readable label.
    Intended for visual output formatting in terminal environments.
    """
    EMPTY  = (Color.RST,   '      ')
    OK     = (Color.GRN_L, '  OK  ')
    FAILED = (Color.RED_L, 'FAILED')

    @property
    def color(self) -> str:
        """
        Returns the ANSI color code associated with the status.
        Useful for formatting colored terminal output.
        """
        return self.value[0]

    @property
    def label(self) -> str:
        """
        Returns the text label associated with the status.
        Used as the displayed message in the notification banner.
        """
        return self.value[1]

@dataclass
class Filter:
    """
    Criteria used to filter nodes based on specific attributes.

    Each attribute is an optional list used to match against node data.
    Attributes:
        - filter_expr: A filter expression (logical string condition).
        - minfeefilter: Minimum fee rate (in BTC/kvB) to match.
        - service: List of service flags to match.
        - useragent: List of user agent strings to match.
        - version: List of protocol versions to match.
    """
    filter_expr: Optional[str] = None
    minfeefilter: Optional[float] = None
    service: Optional[List[int]] = None
    useragent: Optional[List[str]] = None
    version: Optional[List[int]] = None

criteria = Filter()

@dataclass
class Node:
    """
    Represents a remote node with network connection metadata.

    Attributes:
        - addr: IP address and port of the node.
        - network: Network type (e.g., ipv4, ipv6, onion).
        - conntime: Unix timestamp when the connection was established.
        - services: Service flags advertised by the node.
        - version: Protocol version used by the node.
        - subver: User agent string of the node.
        - minfeefilter: Minimum fee rate of the node.
    """
    addr: str
    network: str
    services: Optional[int] = 0
    conntime: Optional[int] = 0
    version: Optional[int] = 0
    subver: Optional[str] = ''
    minfeefilter: Optional[float] = 0

    def is_empty(self) -> bool:
        """
        Returns whether the node lacks any relevant metadata.
        Useful for detecting placeholder or uninitialized node entries.
        """
        return not (self.conntime or self.services or self.version or self.subver)

allnodes: Dict[str, Node] = {}

@dataclass
class Proxy:
    """
    Represents proxy configuration settings.

    Attributes:
        - ip: IP address of the proxy server.
        - port: Port number of the proxy server.
        - url: Dictionary containing protocol-to-proxy URL mappings.
    """
    ip: Optional[str] = None
    port: Optional[int] = None
    url: Optional[Dict[str, str]] = None

proxy = Proxy()

@dataclass
class ThreadState:
    """
    Manages the lifecycle state of a background thread.

    Attributes:
        - lock: Threading lock used for synchronization.
        - thread: Reference to the running thread instance.
        - started_at: Timestamp when the thread started.
        - finished_at: Timestamp when the thread finished.
    """
    lock: threading.Lock = field(default_factory=threading.Lock)
    thread: Optional[threading.Thread] = None
    started_at: float = 0
    finished_at: float = 0

    def should_wait(self) -> bool:
        """
        Checks if the thread should wait before starting again.
        Returns True if still in waiting period, False otherwise.

        Waiting periods:
            - No wait on first run (finished_at == 0)
            - 900 seconds (15 min) after successful run with nodes
            - 3600 seconds (1 hour) after run with no nodes (duration < 10s)
        """
        if not self.finished_at:
            return False
        elapsed = time() - self.finished_at
        duration = self.finished_at - self.started_at
        wait_time = 900 if duration > 10 else 3600
        return elapsed < wait_time

threadctl = ThreadState()

# Default port for I2P SOCKS5 proxy
DEFAULT_I2P_SOCKS_PORT: int = 4447

# Default port for Tor SOCKS5 proxy
DEFAULT_TOR_SOCKS_PORT: int = 9050

# Default ban duration in seconds (1 year)
BANTIME: int = 365 * 24 * 60 * 60

# List of banned addresses
listbanned: List[str] = []

# Default logger for recording log messages
logger: Logger = logging.getLogger(__name__)

# Default initial options
options: dict = {'enable_unban': False}

# Default settings for bitcoin.rpc.Proxy
rpc_conf: dict = {
    'service_url': None,
    'btc_conf_file': None,
    'timeout': 30
}

def banner():
    """
    Prints a stylized ASCII banner to standard output.

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
    """
    Builds and returns the command-line argument parser.

    Defines the supported options and filtering criteria for running the script.
    Includes help and usage examples.
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
              %(prog)s -rpcurl http://user:pass@192.168.0.10:8332 -u 'Knots'

            Note:
              When using simple filters (-m, -s, -u, -v) alongside -f, nodes matching *any* of the conditions will be selected.
            '''),
        formatter_class=RawDescriptionHelpFormatter
    )
    parser.add_argument('-h', '--help', action='help', help=SUPPRESS)
    argrp_opt = parser.add_argument_group('Options')
    argrp_opt.add_argument('-conf', metavar="'str'", type=str,
        help='Specify the Bitcoin node configuration file.')
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

def check_bitcoind():
    """
    Verifies connectivity with the bitcoin node using RPC.

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
    except Exception as e: # pylint: disable=broad-exception-caught
        mark(Status.FAILED, f'{e}\r\n')
        sys.exit(1)

    mark(Status.OK, f"Checked access to bitcoin node via RPC.{' ' * 5}")

def compile_node_filter(expr: str) -> str:
    """
    Translates a simplified filter expression string into a valid Python expression.

    This function allows users to write human-friendly filter conditions using keywords
    like 'mff', 'srv', 'ua', and 'ver', along with basic boolean operators. The resulting
    expression is compatible with eval() and can be used to match node attributes.

    Supported transformations:
      - &&, ||, !           → and, or, not
      - mff N               → node.minfeefilter > N
      - srv N               → (node.services & (1 << N))
      - ua 'pattern'        → re.search(r'pattern', node.subver)
      - ver N               → node.version == N
      - ver >= N            → node.version >= N

    Parameters:
        expr (str): A user-provided filter string.

    Returns:
        str: A valid Python expression string suitable for eval().

    Note:
        The returned string is intended to be used with eval().
        Always ensure that 'node' and 're' are properly scoped and trusted.
    """

    # Logical operators
    expr = re.sub(r'\s*&&\s*', ' and ', expr)
    expr = re.sub(r'\s*\|\|\s*', ' or ', expr)
    expr = re.sub(r'(?<!\w)!(?!=)', 'not ', expr) # convert ! to not, avoid !=

    # Match expressions
    expr = re.sub(r'\bmff\s+([\d.]+)', r'node.minfeefilter > \1', expr)
    expr = re.sub(r'\bsrv\s+(\d+)', r'(node.services & (1 << \1))', expr)
    expr = re.sub(r'\bua\s+[\'"](.+?)[\'"]', r"re.search(r'\1', node.subver)", expr)
    expr = re.sub(r'\bver\s+(\d+)', r'node.version == \1', expr)
    expr = re.sub(r'\bver\s*([=!<>]+)\s*(\d+)', r'node.version \1 \2', expr)

    return expr

def exec_getpeerinfo():
    """
    Retrieves and processes the current peer information from bitcoind.

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
    except Exception as e: # pylint: disable=broad-exception-caught
        mark(Status.FAILED, f'Could not load peers info. [{e}]', False)
        return

    for peer in peerinfo:
        conntime = peer.get('conntime')
        network = peer.get('network')
        subver = peer.get('subver')
        if int(time()) - conntime <= 15 or not subver or network == 'not_publicly_routable':
            continue

        node = Node(
            addr=peer.get('addr'),
            network=network,
            services=int(peer.get('services'), 16),
            conntime=conntime,
            version=peer.get('version'),
            subver=subver,
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
            except Exception as e: # pylint: disable=broad-exception-caught
                mark(Status.FAILED,
                    f'Could not disconnect address {node.addr} '
                    f'({str(node.version)}{node.subver}) '
                    f'[{e}]', False)
            continue

def exec_setban(only_recents: bool):
    """
    Bans nodes from the Bitcoin network based on connection time and filtering criteria.

    Iterates over all known nodes and bans those that match filtering rules and are not
    already banned. For each node to ban, invokes the 'setban' RPC command to
    add a ban for a predefined duration (BANTIME).

    Parameters:
        - only_recents: If True, only considers nodes connected within the last 5 minutes.
    """
    now = time()
    try:
        rpc_proxy = BitcoinRPCProxy(**rpc_conf)
    except Exception: # pylint: disable=broad-exception-caught
        return

    for address, node in allnodes.items():
        if node.is_empty() or (only_recents and node.conntime < now - 300):
            continue

        msg = (
            f'Node: net={node.network}, services={node.services}, '
            f'version={str(node.version)}{node.subver}'
        )
        try:
            if match_node(node) and address not in listbanned:
                rpc_proxy.call('setban', address, 'add', BANTIME)
                listbanned.append(address)
                stamp(msg.replace('Node:', 'Node banned:', 1))
            elif options['enable_unban'] and not match_node(node) and address in listbanned:
                rpc_proxy.call('setban', address, 'remove')
                listbanned.remove(address)
                stamp(msg.replace('Node:', 'Node unbanned:', 1))
        except JSONRPCError as e:
            msg = f'Unable to send the setban request to {address}'
            if e.args[0].get('code') == -23:
                stamp(f'{msg} (already banned)')
            elif e.args[0].get('code') == -30:
                stamp(f'{msg} (already unbanned)')
            else:
                mark(Status.FAILED, f"{msg} [{e.args[0].get('message')}]", False)
        except Exception as e: # pylint: disable=broad-exception-caught
            msg = f'Unable to send the setban request to {address}'
            mark(Status.FAILED, f'{msg} [{e}]', False)

def getdata_node(node: Node) -> Optional[Node]:
    """
    Attempt to establish a network connection to a given node and retrieve its version information.

    Sends a Bitcoin protocol 'version' message and reads the response to extract the node's
    version, services, and subversion string. Uses SOCKS5 proxy settings depending on the
    node's network type (I2P, Tor, CJDNS, or none).

    Parameters:
        - node: The node object containing address, port, and network info.

    Returns:
        - Node: The updated node object with version info if successful.
    """
    if not proxy.ip and node.network in {'ipv6', 'cjdns'}:
        sock = socksocket(socket.AF_INET6)
    else:
        sock = socksocket(socket.AF_INET)
    sock.settimeout(10)

    if node.network == 'i2p':
        sock.set_proxy(SOCKS5, '127.0.0.1', DEFAULT_I2P_SOCKS_PORT)
    elif node.network != 'cjdns' and proxy.ip:
        sock.set_proxy(SOCKS5, proxy.ip, proxy.port)
    elif node.network == 'onion':
        sock.set_proxy(SOCKS5, '127.0.0.1', DEFAULT_TOR_SOCKS_PORT)
    else:
        sock.settimeout(5)

    def read_bytes(sock: socksocket, length: int) -> bytes:
        recvbuf = b''
        while len(recvbuf) < length:
            chunk = sock.recv(length - len(recvbuf))
            if not chunk:
                raise RuntimeError
            recvbuf += chunk
        return recvbuf

    try:
        address, port = split_addressport(node.addr)
        sock.connect((address, port))
        msg_version = BitcoinMsgver()
        msg_version.nVersion = 70016
        msg_version.fRelay = False
        sock.send(msg_version.to_bytes())

        while True:
            header = read_bytes(sock, 24)
            payload = read_bytes(sock, int.from_bytes(header[16:20], byteorder='little'))
            match header[4:16].rstrip(b'\x00'):
                case b'version':
                    msg_version = MsgSerializable.from_bytes(header + payload)
                    node.version = int(msg_version.nVersion)
                    node.services = int(msg_version.nServices)
                    node.subver = msg_version.strSubVer.decode('utf-8', errors='ignore')
                    sock.send(BitcoinMsgvack().to_bytes())
                case b'feefilter':
                    node.minfeefilter = float(struct.unpack('<Q', payload)[0]) / 100000000
                    break
    except Exception: # pylint: disable=broad-exception-caught
        pass

    sock.close()
    return node

def load_allnodes():
    """
    Load all known Bitcoin network node addresses into the global allnodes dictionary.

    The function queries the Bitcoin daemon for the total number of known nodes using
    'getaddrmaninfo', then fetches detailed node address information with 'getnodeaddresses'.
    It populates the global allnodes dict with Node instances keyed by their IP address.
    """
    mark(Status.EMPTY, 'Loading known addresses...')

    try:
        nodeaddresses = BitcoinRPCProxy(
            **(rpc_conf | {'timeout': 300})
        ).call('getnodeaddresses', 0)
    except JSONRPCError as e:
        mark(Status.FAILED, f"{e.args[0].get('message')}\r\n")
        sys.exit(1)
    except Exception as e: # pylint: disable=broad-exception-caught
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

def load_listbanned():
    """
    Load the list of banned node addresses into the global listbanned list.

    The function calls the Bitcoin daemon's 'listbanned' RPC command to retrieve
    currently banned addresses, clears the existing listbanned, and updates it
    with the IP addresses extracted from the banned entries.
    """
    mark(Status.EMPTY, 'Loading banned addresses...')

    try:
        bannedaddresses = BitcoinRPCProxy(**rpc_conf).call('listbanned')
    except JSONRPCError as e:
        mark(Status.FAILED, f"{e.args[0].get('message')}\r\n")
        sys.exit(1)
    except Exception as e: # pylint: disable=broad-exception-caught
        mark(Status.FAILED, f'{e}\r\n')
        sys.exit(1)

    listbanned.clear()
    for node in bannedaddresses:
        address = node['address'].split('/')[0]
        listbanned.append(address)

        if not options['enable_unban'] or allnodes.get(address):
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

# pylint: disable=too-many-branches
def main():
    """
    Entry point of the program that parses command-line arguments and initializes
    program state accordingly.

    - Parses CLI arguments using the argument parser built by `build_parser()`.
    - Sets filtering criteria based on user input such as minfeefilter, service,
      useragent regex patterns, and version.
    - Validates regex patterns provided for useragent and exits if invalid.
    - Configures proxy settings if provided.
    - If no criteria are specified, prints help and exits.
    - Otherwise, calls the `start()` function to begin processing.
    """
    parser = build_parser()
    args = parser.parse_args()

    options['enable_unban'] = args.unban

    if args.rpcurl:
        rpc_conf['service_url'] = args.rpcurl
    elif args.conf:
        rpc_conf['btc_conf_file'] = args.conf

    if args.minfeefilter:
        criteria.minfeefilter = args.minfeefilter

    if args.service:
        criteria.service = args.service

    if args.useragent:
        try:
            for pattern in args.useragent:
                re.compile(pattern)
            criteria.useragent = args.useragent
        except re.error as e:
            print(f'Invalid regex for -u: {e}')
            sys.exit(1)

    if args.version:
        criteria.version = args.version

    if args.filter:
        # Validate and compile user-defined filter expression
        parsed_expr = compile_node_filter(args.filter)
        try:
            ast.parse(parsed_expr, mode='eval')
            criteria.filter_expr = parsed_expr
            node_test = Node(addr='', network='')
            # pylint: disable=eval-used
            eval(criteria.filter_expr, {}, {'node': node_test, 're': re})
        except Exception as e: # pylint: disable=broad-exception-caught
            msg = getattr(e, 'msg', str(e))
            print(f'Invalid filter expression: {msg}')
            sys.exit(1)

    if args.proxy:
        proxy.ip, proxy.port = split_addressport(args.proxy, DEFAULT_TOR_SOCKS_PORT)
        proxy.url = {
            'http': f'socks5h://{proxy.ip}:{proxy.port}',
            'https': f'socks5h://{proxy.ip}:{proxy.port}'
        }

    if all(value is None for value in criteria.__dict__.values()):
        parser.print_help()
    else:
        start()

def mark(status: Union[Color, Status], text: str, answer: bool=True):
    """
    Display a colored status label and message on the console.

    Parameters:
        - status: Status or Color instance defining label and color.
        - text: Message to print.
        - answer: If True, overwrites the current line; else prints new line.
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
    """
    Check if a node matches the defined criteria.

    Parameters:
        - node: The network node to evaluate.

    Returns:
        - bool: True if the node matches any filter, False otherwise.
    """
    if criteria.minfeefilter:
        if node.minfeefilter > criteria.minfeefilter:
            return True

    if criteria.version:
        if str(node.version) in map(str, criteria.version):
            return True

    if criteria.useragent:
        if any(re.search(p, node.subver) for p in criteria.useragent):
            return True

    if criteria.service:
        if any(node.services & (1 << s) for s in criteria.service):
            return True

    if criteria.filter_expr:
        # pylint: disable=eval-used
        if eval(criteria.filter_expr, {}, {'node': node, 're': re}):
            return True

    return False

def probe_nodes():
    """
    Probes nodes without a connection timestamp to retrieve their metadata.

    Uses a thread pool to concurrently connect to nodes that have not yet been contacted.
    Updates each node's connection time, version, services, and user agent upon success.
    """
    threadctl.started_at = time()

    if options['enable_unban']:
        list_nodes = list(allnodes.values())
    else:
        list_nodes = [node for node in list(allnodes.values()) if node.is_empty()]

    if not list_nodes:
        stamp('No nodes found. Probe nodes thread paused for 1 hour')
        threadctl.finished_at = time()
        return

    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = [executor.submit(getdata_node, node) for node in list_nodes]
        for future in as_completed(futures):
            node = future.result()
            if not node or node.is_empty():
                continue
            address, _ = split_addressport(node.addr)
            allnodes[address].conntime = int(time())
            allnodes[address].services = node.services
            allnodes[address].version = node.version
            allnodes[address].subver = node.subver
            allnodes[address].minfeefilter = node.minfeefilter

    stamp('Probe nodes thread paused for 15 minutes')
    threadctl.finished_at = time()

def snapshot_bitnodes():
    """
    Downloads the latest node snapshot from Bitnodes API and updates the `allnodes` map.

    Updates the `allnodes` map with addresses of missing nodes so that the information
    can be accurately consulted later.
    """
    mark(Status.EMPTY, 'Downloading latest snapshot from Bitnodes...')

    try:
        response = requests.get(
            'https://bitnodes.io/api/v1/snapshots/latest/',
            proxies=proxy.url,
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
    """
    Splits an address string into (address, port), handling IPv4, IPv6, and default port cases.

    Parameters:
        - addressport: Address string, optionally with port (e.g., '1.2.3.4:8333', '[::1]:8333').
        - dport: Default port to use if none is specified.

    Returns:
        - Tuple: A tuple of (address, port).
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

def stamp(text: str):
    """
    Prints a timestamped log message to stdout with color formatting.

    Parameters:
        - text: The log message to display.
    """
    date = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
    try:
        sys.stdout.write(f'\r\n{Color.CYN}{date}{Color.RST} {text}')
        sys.stdout.flush()
    except (BrokenPipeError, ValueError):
        try:
            sys.stdout.close()
        except Exception: # pylint: disable=broad-exception-caught
            pass
        sys.stderr.write(f'\r\n{Color.CYN}{date}{Color.RST} {text}')
        sys.stderr.flush()
    logger.info(text)

def start():
    """
    Initializes and starts the main monitoring loop.

    Loads banned and known node data, periodically refreshes the Bitnodes snapshot,
    spawns a background thread to probe new nodes, and manages peer banning logic
    at fixed intervals. Handles graceful termination on keyboard interrupt.
    """
    banner()

    # Configure logger to write to debug.log file only (no console output)
    # Level: INFO | Mode: append | Format: local timestamp (ISO 8601-like, no timezone)
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
            with threadctl.lock:
                thread_dead = threadctl.thread is None or not threadctl.thread.is_alive()
                if thread_dead and not threadctl.should_wait():
                    load_listbanned()
                    load_allnodes()
                    snapshot_bitnodes()
                    msg = {True: 'started', False: 'resumed'}[threadctl.thread is None]
                    stamp(f'Probe nodes thread {msg}')
                    threadctl.thread = threading.Thread(target=probe_nodes)
                    threadctl.thread.start()
                    only_recents = False
                else:
                    only_recents = True
            exec_getpeerinfo()
            exec_setban(only_recents)
            sleep(10)
    except KeyboardInterrupt:
        stamp('Shutdown: done\r\n')
        os._exit(0)

if __name__ == '__main__':
    main()
