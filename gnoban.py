#!/usr/bin/python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 CaesarCoder <caesrcd@tutamail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/licenses/mit-license.php.
"""
gnoban.py - A script to analyze and ban Bitcoin nodes based on custom criteria.

This script evaluates known nodes on your local full node and the Bitnodes Snapshot API.
It supports filtering by service flags, user agent, and protocol version to ban remote
nodes on your full node.

Author: CaesarCoder <caesrcd@tutamail.com>
License: MIT
"""

# Python module imports
import json
import re
import socket
import struct
import subprocess
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
from hashlib import sha256
from time import time, sleep
from typing import Dict, List, Optional, Tuple, Union
from zlib import decompress

# Third-party module imports
import requests
from socks import (
    GeneralProxyError,
    ProxyConnectionError,
    socksocket,
    SOCKS5
)

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
        - service: List of service flags to match.
        - useragent: List of user agent strings to match.
        - version: List of protocol versions to match.
    """
    service: Optional[List[int]] = None
    useragent: Optional[List[str]] = None
    version: Optional[List[int]] = None

criteria = Filter()

@dataclass
class Node:
    """
    Represents a remote node with network connection metadata.

    Attributes:
        - address: IP address of the node.
        - port: Port number used by the node.
        - network: Network type (e.g., ipv4, ipv6, onion).
        - conntime: Unix timestamp when the connection was established.
        - services: Service flags advertised by the node.
        - version: Protocol version used by the node.
        - subver: User agent string of the node.
    """
    address: str
    port: int
    network: str
    conntime: Optional[int] = 0
    services: Optional[int] = 0
    version: Optional[int] = 0
    subver: Optional[str] = ''

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
        - stop: Event used to signal thread termination.
        - thread: Reference to the running thread instance.
    """
    lock: threading.Lock = field(default_factory=threading.Lock)
    stop: threading.Event = field(default_factory=threading.Event)
    thread: Optional[threading.Thread] = None

threadctl = ThreadState()

# Default port for I2P SOCKS5 proxy
DEFAULT_I2P_SOCKS_PORT: int = 4447

# Default port for Tor SOCKS5 proxy
DEFAULT_TOR_SOCKS_PORT: int = 9050

# Default ban duration in seconds (1 year)
BANTIME: int = 365 * 24 * 60 * 60

listbanned: List[str] = []

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
    Constructs and returns the command-line argument parser.

    Defines supported options for filtering nodes by service flags, user agent strings,
    protocol versions, and proxy settings. Includes usage help, examples, and service
    flag definitions in the epilog.
    """
    parser = ArgumentParser(
        add_help=False,
        usage='python %(prog)s [options]',
        description=(
            'Scan and evaluate known nodes to determine which should be banned '
            'based on specified criteria.'
        ),
        epilog=textwrap.dedent('''\
            Services Flags:
              0   = NODE_NETWORK
              2   = NODE_BLOOM
              3   = NODE_WITNESS
              6   = NODE_COMPACT_FILTERS
              10  = NODE_NETWORK_LIMITED
              11  = NODE_P2P_V2
              26  = NODE_KNOTS (experiments)
              29  = NODE_LIBRE_RELAY (experiments)

            Note:
            If multiple criteria are specified, nodes matching *any* of them will be selected.

            Examples:
              python %(prog)s -s 26 -u 'Knots'
            '''),
        formatter_class=RawDescriptionHelpFormatter
    )
    parser.add_argument('-h', '--help', action='help', help=SUPPRESS)
    parser.add_argument('-proxy', metavar='ip[:port]', type=str,
        help='Connect through SOCKS5 proxy.')
    parser.add_argument('-s', dest='service', metavar='num', type=int, nargs='+',
        help='Service flags provided by the node.')
    parser.add_argument('-u', dest='useragent', metavar="'str'", type=str, nargs='+',
        help="Matches part of the node's user agent.")
    parser.add_argument('-v', dest='version', metavar='num', type=int, nargs='+',
        help='Protocol version of the node.')

    return parser

def check_bitcoind():
    """
    Verifies connectivity with the bitcoind RPC interface.

    Executes the 'uptime' RPC command via bitcoin-cli to check if the node is reachable.
    Displays a status message based on the result. Exits the program if the check fails
    due to command errors, missing binary, or permission issues.
    """
    message = 'Checking access to bitcoind RPC'
    mark(Status.EMPTY, f'{message}...')

    try:
        rpc_bitcoincli('uptime')
    except subprocess.CalledProcessError as e:
        mark(Status.FAILED, e.stderr.decode())
        clean_exit(1)
    except (FileNotFoundError, OSError, PermissionError) as e:
        mark(Status.FAILED, e)
        clean_exit(1)

    mark(Status.OK, f"{message}.{' ' * 5}")

def clean_exit(code: int, exec_exit: bool=True):
    """
    Gracefully shuts down the background thread and optionally exits the program.

    Ensures that if a background thread is running, it is signaled to stop and joined
    before continuing. Optionally calls sys.exit() with the given exit code.

    Parameters:
        - code: Exit code to return if exiting the program.
        - exec_exit: Whether to actually call sys.exit(). Defaults to True.
    """
    with threadctl.lock:
        if threadctl.thread is not None and threadctl.thread.is_alive():
            stamp('Shutdown: In progress...')
            threadctl.stop.set()
            threadctl.thread.join()
            stamp('Shutdown: done')
    if exec_exit:
        sys.exit(code)

def exec_getpeerinfo():
    """
    Retrieves and processes the current peer information from bitcoind.

    Fetches peer data via the 'getpeerinfo' RPC command, parses the JSON output,
    and updates the internal node list accordingly. Filters out nodes based on
    network visibility and ban list criteria. Attempts to disconnect banned or
    mismatched nodes by invoking the 'disconnectnode' RPC command.
    """
    try:
        output = rpc_bitcoincli('getpeerinfo')
        peerinfo = json.loads(output)
    except subprocess.CalledProcessError as e:
        mark(Status.FAILED, f'Could not load peer info.\r\n{e.stderr.decode()}', False)
        clean_exit(1)

    for peer in peerinfo:
        addressport = peer.get('addr', '')
        network = peer.get('network', '')
        services = int(peer.get('services', '0'), 16)
        version = peer.get('version', 0)
        subver = peer.get('subver', '')
        if not (addressport and network and subver) or network == 'not_publicly_routable':
            continue

        address, port = split_addressport(addressport)
        conntime = peer.get('conntime')
        if not isinstance(conntime, int):
            conntime = int(time())

        node = Node(
            address=address,
            port=port or 8333,
            network=network,
            conntime=conntime,
            services=services,
            version=version,
            subver=subver
        )

        node_old = allnodes.get(address)
        if address != '127.0.0.1' and (not node_old or conntime != node_old.conntime):
            allnodes[address] = node
        if address == '127.0.0.1' or node_old:
            if not match_node(node) or (address != '127.0.0.1' and address not in listbanned):
                continue
            ver = f'{str(version)}{subver}'
            try:
                rpc_bitcoincli('disconnectnode', addressport)
                stamp(f'Node disconnected: net={network}, services={services}, version={ver}')
            except subprocess.CalledProcessError as e:
                if e.returncode != 29:
                    mark(Status.FAILED,
                        f'Could not disconnect node {addressport,} ({ver})'
                        f'\r\n{e.stderr.decode()}',
                        False)
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

    for address, node in allnodes.items():
        if only_recents and node.conntime < now - 300:
            continue

        version = node.version
        subver = node.subver
        if address in listbanned or not match_node(node):
            continue

        network = node.network
        services = node.services
        ver = f'{str(version)}{subver}'
        try:
            rpc_bitcoincli('setban', address, 'add', str(BANTIME))
            listbanned.append(address)
            stamp(f'Node banned: net={network}, services={services}, version={ver}')
        except subprocess.CalledProcessError as e:
            msg = f'Could not ban address {address}'
            if e.returncode == 23:
                stamp(f'{msg} (already banned)')
            else:
                mark(Status.FAILED, f'{msg}\r\n{e.stderr.decode()}', False)

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
    if threadctl.stop.is_set():
        return None

    if not proxy.ip and node.network in {'ipv6', 'cjdns'}:
        family = socket.AF_INET6
    else:
        family = socket.AF_INET
    sock = socksocket(family)
    sock.settimeout(10)

    if node.network == 'i2p':
        sock.set_proxy(SOCKS5, '127.0.0.1', DEFAULT_I2P_SOCKS_PORT)
    elif node.network != 'cjdns' and proxy.ip:
        sock.set_proxy(SOCKS5, proxy.ip, proxy.port)
    elif node.network == 'onion':
        sock.set_proxy(SOCKS5, '127.0.0.1', DEFAULT_TOR_SOCKS_PORT)
    else:
        sock.settimeout(5)

    try:
        sock.connect((node.address, node.port))
    except (socket.gaierror, GeneralProxyError, OSError, ProxyConnectionError):
        sock.close()
        return None

    def read_bytes(sock: socksocket, length: int) -> bytes:
        data = b''
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                raise ConnectionResetError
            data += chunk
        return data

    magic = b'\xf9\xbe\xb4\xd9'
    payload = struct.pack('<iQQ26s26sQ', 70015, 0, int(time()), b'\x00'*26, b'\x00'*26, 0)
    payload += b'\x00' + struct.pack('<i', 0) + b'\x00'
    header = (
        magic +
        b'version'.ljust(12, b'\x00') +
        struct.pack('<I', len(payload)) +
        sha256(sha256(payload).digest()).digest()[:4]
    )
    sock.sendall(header + payload)

    try:
        if read_bytes(sock, 4) != magic:
            raise ValueError
        version_msg = read_bytes(sock, 20)
        length = struct.unpack('<I', version_msg[12:16])[0]
        payload = read_bytes(sock, length)

        node.version = int(struct.unpack('<i', payload[0:4])[0])
        node.services = int(struct.unpack('<Q', payload[4:12])[0])
        useragent_len = payload[80]
        if len(payload) < 81 + useragent_len:
            raise ValueError
        node.subver = payload[81:81 + useragent_len].decode('utf-8', errors='ignore')
    except (ConnectionResetError, TimeoutError, ValueError):
        return None
    finally:
        sock.close()

    return node

def load_allnodes():
    """
    Load all known Bitcoin network node addresses into the global allnodes dictionary.

    The function queries the Bitcoin daemon for the total number of known nodes using
    'getaddrmaninfo', then fetches detailed node address information with 'getnodeaddresses'.
    It populates the global allnodes dict with Node instances keyed by their IP address.
    """
    message = 'Loading known addresses'
    mark(Status.EMPTY, f'{message}...')

    output = rpc_bitcoincli('getaddrmaninfo')
    addrmaninfo = json.loads(output)

    amount_nodes = addrmaninfo.get('all_networks', {}).get('total', 0)
    if amount_nodes == 0:
        return

    output = rpc_bitcoincli('getnodeaddresses', str(amount_nodes))
    nodeaddresses = json.loads(output)

    for node in nodeaddresses:
        allnodes[node['address']] = Node(
            address=node['address'],
            port=node['port'] or 8333,
            network=node['network']
        )

    mark(Status.OK, f'{message}. ({len(nodeaddresses)} entries)')

def load_listbanned():
    """
    Load the list of banned node addresses into the global listbanned list.

    The function calls the Bitcoin daemon's 'listbanned' RPC command to retrieve
    currently banned addresses, clears the existing listbanned, and updates it
    with the IP addresses extracted from the banned entries.
    """
    message = 'Loading banned addresses'
    mark(Status.EMPTY, f'{message}...')

    output = rpc_bitcoincli('listbanned')
    bannedaddresses = json.loads(output)

    listbanned.clear()
    listbanned.extend(node['address'].split('/')[0] for node in bannedaddresses)
    mark(Status.OK, f'{message}. ({len(listbanned)} entries)')

def main():
    """
    Entry point of the program that parses command-line arguments and initializes
    program state accordingly.

    - Parses CLI arguments using the argument parser built by `build_parser()`.
    - Sets filtering criteria based on user input such as service, useragent regex patterns,
      and version.
    - Validates regex patterns provided for useragent and exits if invalid.
    - Configures proxy settings if provided.
    - If no criteria are specified, prints help and exits.
    - Otherwise, calls the `start()` function to begin processing.
    """
    parser = build_parser()
    args = parser.parse_args()

    if args.service:
        criteria.service = args.service

    if args.useragent:
        try:
            for pattern in args.useragent:
                re.compile(pattern)
            criteria.useragent = args.useragent
        except re.error as e:
            print(f'Invalid regex for -u: {e}')
            clean_exit(1)

    if args.version:
        criteria.version = args.version

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

def match_node(node: Node) -> bool:
    """
    Check if a node matches the defined criteria.

    Parameters:
        - node: The network node to evaluate.

    Returns:
        - bool: True if the node matches any filter, False otherwise.
    """
    if criteria.version:
        if str(node.version) in map(str, criteria.version):
            return True

    if criteria.useragent:
        if any(re.search(p, node.subver) for p in criteria.useragent):
            return True

    if criteria.service:
        if any(node.services & (1 << s) for s in criteria.service):
            return True

    return False

def probe_nodes():
    """
    Probes nodes without a connection timestamp to retrieve their metadata.

    Uses a thread pool to concurrently connect to nodes that have not yet been contacted.
    Updates each node's connection time, version, services, and user agent upon success.
    """
    empty_nodes = [node for addr, node in list(allnodes.items()) if not node.conntime]
    if not empty_nodes:
        return

    stamp('Probe nodes thread start')
    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = [executor.submit(getdata_node, node) for node in empty_nodes]
        for future in as_completed(futures):
            data = future.result()
            if not data:
                continue
            address = data.address
            allnodes[address].conntime = int(time())
            allnodes[address].services = data.services
            allnodes[address].version = data.version
            allnodes[address].subver = data.subver
    stamp('Probe nodes thread exit')

def rpc_bitcoincli(*args) -> str:
    """
    Executes a bitcoin-cli RPC command and returns the output as a string.

    Waits for the Bitcoin Core RPC server to become available (30s timeout) before executing
    the command. Raises an exception on failure, allowing callers to handle errors properly.

    Parameters:
        - *args: Positional arguments to pass to the bitcoin-cli command.

    Returns:
        - str: The decoded output from the command.
    """
    return subprocess.check_output(
        ['bitcoin-cli', '-rpcwait', '-rpcwaittimeout=30'] + list(args),
        stderr=subprocess.PIPE
    ).decode()

def snapshot_bitnodes():
    """
    Downloads the latest node snapshot from Bitnodes API and updates the `allnodes` map.

    Nodes with outdated connection timestamps or missing subversion info are replaced.
    Applies network type heuristics (IPv4, IPv6, or Onion) based on address format.
    """
    message = 'Downloading latest snapshot from Bitnodes'
    mark(Status.EMPTY, f'{message}...')

    try:
        response = requests.get(
            'https://bitnodes.io/api/v1/snapshots/latest/',
            proxies=proxy.url,
            timeout=30)
        response.raise_for_status()
        data = response.json()
        nodeaddresses = data.get('nodes', {})
    except requests.RequestException as e:
        mark(Status.FAILED, f'Error: {e}')
        return

    for addressport, info in nodeaddresses.items():
        if len(info) < 3:
            continue

        conntime = int(info[2])
        address, port = split_addressport(addressport)
        node = allnodes.get(address)
        if node and conntime < node.conntime and node.subver != '':
            continue

        if address.endswith('.onion'):
            network = 'onion'
        elif ':' in address:
            network = 'ipv6'
        else:
            network = 'ipv4'

        allnodes[address] = Node(
            address=address,
            port=port,
            network=network,
            conntime=conntime,
            services=int(info[3]),
            version=int(info[0]),
            subver=info[1]
        )

    mark(Status.OK, f'{message}. ({len(nodeaddresses)} entries)')

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
    sys.stdout.write(f'\r\n{Color.CYN}{date}{Color.RST} {text}')
    sys.stdout.flush()

def start():
    """
    Initializes and starts the main monitoring loop.

    Loads banned and known node data, periodically refreshes the Bitnodes snapshot,
    spawns a background thread to probe new nodes, and manages peer banning logic
    at fixed intervals. Handles graceful termination on keyboard interrupt.
    """
    banner()
    try:
        check_bitcoind()
        load_listbanned()
        load_allnodes()

        next_bitnodes_refresh = time()
        only_recents = False
        while True:
            now = time()

            if now >= next_bitnodes_refresh:
                snapshot_bitnodes()
                next_bitnodes_refresh = now + 10800
                only_recents = False
                with threadctl.lock:
                    if threadctl.thread is None or not threadctl.thread.is_alive():
                        threadctl.thread = threading.Thread(target=probe_nodes)
                        threadctl.thread.start()

            exec_getpeerinfo()
            exec_setban(only_recents)
            only_recents = True

            sleep(60)
    except KeyboardInterrupt:
        clean_exit(0)

if __name__ == '__main__':
    main()
