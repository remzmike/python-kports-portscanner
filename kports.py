#!/usr/bin/env python2
"""
kports v05

My tcp and udp port scanner, using non-blocking sockets.

The tcp scan is a simple connect scan using epoll.

The udp scan is more complicated. A closed port is one where subsequent sends
throw an ECONNREFUSED errno. This is effectively detecting ICMP "Destination
Unreachable" type 3 code 3 errors. An open port is one where a udp response is
received. A port may also be "possibly open" due to the lack of a response or
error from the target. These are returned as a separate list by udp_scan_ex.

The advanced udp scan also accounts for rate-limiting of ICMP port unreachable
errors at the target. Because of this, advanced scanning of 1024 udp ports can
take around 20 minutes using udp_scan_ex with the default arguments.

HOWEVER, this script will do a faster udp scan by default, checking for
responsive, obviously open ports. The udp_scan function makes a special call
to udp_scan_ex effectively disabling the advanced scanning features.

This udp scanning technique is called the "lame" udp scan by nmap.

You can modify some of this behavior using the global constants.

See `kports -h` for usage information.

example: ./kports.py -sa scanme.nmap.org
----------------------------------------
{
    "status": "fqdn resolves",
    "target": "scanme.nmap.org",
    "tcp": [
        22,
        80
    ],
    "udp": [
        67,
        68,
        123,
        137,
        161
    ]
}

original request:
-----------------
Create a python script using python 2.7.x that will take a single input
parameter of either an IP or a FQDN and perform a basic port scan on it.

This script must run on Linux, and return a JSON object that holds the results.

If it is a valid ip, just scan the IP for responding tcp/udp ports.

If it is not an IP, assume it is a FQDN and see if it resolves, and if so, scan
the target for responding TCP/UDP ports. You can limit the scan to ports lower
than 1024.

Feel free to add additional data to the sample JSON output below, or format it
differently, if you believe it to be useful in the context of the script.

Examples:
1) python pgm.py 1.2.3.4
{
                'target': '64.157.211.4',
                'status': 'valid ip',
                'tcp': [22,23,80,443],
                'udp': [ ]
}

2) python pgm.py www.ibm.com
{
                'target': 'www.ibm.com',
                'status': 'fqdn resolves',
                'tcp': [22,23,80,443],
                'udp': [53]
}

3) python pgm.py www.sdsds.xxz
{
                'target': 'www.sdsds.xxz',
                'status': 'fqdn does not resolve'
}
"""

from __future__ import division, print_function
import argparse
import errno
import json
import math
import random
import select
import socket
import time

# some of these are tricky to configure
TCP_ASYNC_LIMIT = 256      # number of tcp ports to scan concurrently
TCP_CONNECT_POLLTIME = 12  # seconds poll waits for async tcp connects
UDP_ASYNC_LIMIT = 256      # max udp ports to scan concurrently
UDP_RETRIES = 8            # default number of udp retransmissions
UDP_WAIT = 1               # default wait seconds before retry + receive
UDP_ICMP_RATE_LIMIT = 1    # wait seconds after inferred icmp unreachable
# advanced udp scanning accuracy improves when you match server icmp rate limit
# because you will get less false positives ('maybe opens') from timeouts


class Probe():
    """
    simple probe state, one per ip:port per scan type
    """
    def __init__(self, ip, port, _type=socket.SOCK_STREAM):
        self.type = _type
        self.ip = ip
        self.port = port
        self.status = None
        self.socket = socket.socket(socket.AF_INET, _type)

    def handle_udp_econnrefused(self):
        # even numbered sends will fail with econnrefused
        # this is used to detect icmp unreachable errors
        self.status = False
        self.socket.close()
        verbose('udp port closed', self.port)

    def handle_udp_receive(self):
        self.status = True
        self.socket.close()
        verbose('udp port open', self.port)


def udp_scan(ip, ports):
    """
    only scan for obviously responsive udp ports
    returns: open_ports
    """
    open_ports = udp_scan_ex(ip, ports,
                             8,    # send packets at start
                             0,    # no retries, since we sent packets
                             8,    # wait seconds before trying to receive
                             0,    # override icmp rate limit wait
                             )[0]
    return open_ports


def udp_scan_ex(ip, ports, initial_sends=1, retries=UDP_RETRIES, wait=UDP_WAIT,
                icmp_rate_limit=UDP_ICMP_RATE_LIMIT):
    """
    scan for open+filtered udp ports
    returns: open_ports, maybe_open_ports
    """
    verbose('udp scanning %d ports' % (len(ports)))

    probes = []
    for port in ports:
        probe = Probe(ip, port, socket.SOCK_DGRAM)
        probes.append(probe)
        sock = probe.socket

        sock.setblocking(0)
        sock.connect((probe.ip, probe.port))  # allow icmp unreachable detect

        # initial_sends allows us to implement udp_scan as a simple wrapper
        # at the expense of slightly complicating udp_scan_ex
        # initial_sends = (initial_sends & ~1) + 1  # always odd
        for i in range(initial_sends):
            if probe.status is not None:
                continue
            try:
                sock.send('\x00')
            except socket.error as ex:
                if ex.errno == errno.ECONNREFUSED:
                    probe.handle_udp_econnrefused()
                    break
                else:
                    raise

    for i in range(retries+1):

        time.sleep(wait)

        for probe in probes:
            if probe.status is not None:
                continue
            sock = probe.socket
            try:
                sock.send('\x01')
            except socket.error as ex:
                # 2nd send icmp trick to detect closed ports
                # print ex, '* 2nd send', errno.errorcode[ex.errno]
                if ex.errno == errno.ECONNREFUSED:
                    probe.handle_udp_econnrefused()
                    # sleep to deal with icmp error rate limiting
                    time.sleep(icmp_rate_limit)
                    continue
                else:
                    raise

            try:
                sock.recvfrom(8192)
                probe.handle_udp_receive()
                continue
            except socket.error as ex:
                if ex.errno == errno.ECONNREFUSED:
                    verbose('udp recv failed',
                            errno.errorcode[ex.errno], ex, probe.port)
                    continue
                elif ex.errno != errno.EAGAIN:
                    verbose('udp recv failed',
                            errno.errorcode[ex.errno], ex, probe.port)
                    raise

    open_ports = []
    maybe_open_ports = []
    for probe in probes:
        if probe.status is False:
            continue
        elif probe.status:
            verbose('udp port open', probe.port)
            open_ports.append(probe.port)
        else:
            verbose('udp port maybe open', probe.port)
            maybe_open_ports.append(probe.port)
            probe.socket.close()

    return open_ports, maybe_open_ports


def tcp_scan(ip, ports):
    verbose('tcp scanning %d ports' % (len(ports)))

    open_ports = []
    probes = []
    fileno_map = {}  # {fileno:probe}

    poll = select.epoll(len(ports))
    for port in ports:
        probe = Probe(ip, port)
        sock = probe.socket
        fileno_map[sock.fileno()] = probe

        sock.setblocking(0)
        result = sock.connect_ex((probe.ip, probe.port))

        if result == 0:
            verbose('tcp port immediate connect', port)
            open_ports.append(port)
        elif result == errno.EINPROGRESS:
            # print('pending', probe.port, errno.errorcode[result])
            poll.register(probe.socket,
                          select.EPOLLOUT | select.EPOLLERR | select.EPOLLHUP)
            probes.append(probe)
        else:
            verbose('tcp connect fail', port, result, errno.errorcode[result])

    if len(probes) > 0:
        time.sleep(1)

        events = poll.poll(TCP_CONNECT_POLLTIME)

        for fd, flag in events:
            probe = fileno_map[fd]
            # print(probe.port, fd, flag)

            error = probe.socket.getsockopt(socket.SOL_SOCKET,
                                            socket.SO_ERROR)
            if error:
                verbose('tcp connection bad', probe.port, error)
            else:
                verbose('tcp connection good', probe.port)
                open_ports.append(probe.port)

    for probe in probes:
        probe.socket.close()

    poll.close()

    return open_ports


def segment(fn, ip, ports, async_limit):
    loops = int(math.ceil(len(ports)/async_limit))
    open_ports = []
    for i in range(loops):
        start = i*async_limit
        stop = (i+1)*async_limit
        result = fn(ip, ports[start:stop])
        if type(result) == tuple:
            open_ports.extend(result[0])
            open_ports.extend(result[1])
        else:
            open_ports.extend(result)
    return open_ports


def main(target, ports, advanced_udp=False):
    result = dict(target=target, status='')

    valid_target = False
    try:
        # re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',target)
        ip = socket.inet_ntoa(socket.inet_aton(target))
        result['status'] = 'valid ip'
        valid_target = True
    except socket.error:
        # "If it is not an IP, assume it is a FQDN"
        try:
            ip = socket.gethostbyname(target)
            result['status'] = 'fqdn resolves'
            valid_target = True
        except socket.gaierror:
            ip = target
            result['status'] = 'fqdn does not resolve'

    if valid_target:
        random.shuffle(ports)

        verbose('scanning', ip)

        verbose('starting tcp scan, total ports: %d' % (len(ports)))
        tcp_ports = segment(tcp_scan, ip, ports, TCP_ASYNC_LIMIT)
        result['tcp'] = sorted(tcp_ports)

        verbose('starting udp scan, total ports: %d' % (len(ports)))
        if advanced_udp:
            estimated = round(len(ports)/60)+1
            verbose('performing udp scan in advanced mode')
            verbose('rough estimated udp completion: %d minutes' % (estimated))
            udp_ports = segment(udp_scan_ex, ip, ports, UDP_ASYNC_LIMIT)
        else:
            udp_ports = segment(udp_scan, ip, ports, UDP_ASYNC_LIMIT)
        result['udp'] = sorted(udp_ports)

    verbose('--- output ---')
    print(json.dumps(result, sort_keys=True, indent=4, separators=(',', ': ')))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', dest='verbose', action='store_true',
                        help='verbose output')
    parser.add_argument('-s', dest='limited_ports', action='store_true',
                        help='scans only a small list of test ports')
    parser.add_argument('-a', dest='advanced_udp', action='store_true',
                        help='use advanced udp scan to detect \
                        more open ports (SLOW)')
    parser.add_argument('target', help='target ip or fqdn')

    args = parser.parse_args()

    if args.verbose:
        verbose = print
    else:
        verbose = lambda *args: None

    if args.limited_ports:
        ports = [20, 22, 23, 53, 67, 68, 80, 123, 137, 154,
                 161, 162, 443, 631, 727, 8888, 8898]
    else:
        ports = range(1, 1024)

    main(args.target, ports, args.advanced_udp)
