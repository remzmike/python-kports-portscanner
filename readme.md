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