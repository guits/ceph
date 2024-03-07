import socket
import ipaddress
import os
import ctypes
from typing import Dict, Any, List, Optional


class In6Addr(ctypes.Structure):
    _fields_ = [('s6_addr', ctypes.c_uint8 * 16)]


class Sockaddr(ctypes.Structure):
    _fields_ = [('sa_family', ctypes.c_ushort), ('sa_data', ctypes.c_char * 14)]


class Sockaddr_in(ctypes.Structure):
    _fields_ = [
        ('sin_family', ctypes.c_ushort),
        ('sin_port', ctypes.c_uint16),
        ('sin_addr', ctypes.c_uint32),
        ('padding', ctypes.c_char * 8),
    ]


class Sockaddr_in6(ctypes.Structure):
    _fields_ = [
        ('sin6_family', ctypes.c_ushort),
        ('sin6_port', ctypes.c_uint16),
        ('sin6_flowinfo', ctypes.c_uint32),
        ('sin6_addr', In6Addr),
        ('sin6_scope_id', ctypes.c_uint32),
    ]


class SockaddrUnion(ctypes.Union):
    _fields_ = [
        ('Sockaddr', Sockaddr),
        ('Sockaddr_in', Sockaddr_in),
        ('Sockaddr_in6', Sockaddr_in6),
    ]


class Ifa_Ifu(ctypes.Union):
    _fields_ = [('ifu_broadaddr', ctypes.POINTER(Sockaddr)),
                ('ifu_dstaddr', ctypes.POINTER(Sockaddr))]


class Ifaddrs(ctypes.Structure):
    pass


Ifaddrs._fields_ = [
    ('ifa_next', ctypes.POINTER(Ifaddrs)),
    ('ifa_name', ctypes.c_char_p),
    ('ifa_flags', ctypes.c_uint),
    ('ifa_addr', ctypes.POINTER(SockaddrUnion)),
    ('ifa_netmask', ctypes.POINTER(Sockaddr)),
    ('ifa_ifu', Ifa_Ifu),
    ('ifa_data', ctypes.c_void_p),
]


def get_loopback_interface() -> str:
    sysfs_net_dir = '/sys/class/net'

    for iface in os.listdir(sysfs_net_dir):
        if not os.path.exists(os.path.join(sysfs_net_dir, iface, 'device')):
            return iface

    return ''


def dump_interfaces() -> Dict[str, Any]:
    libc = ctypes.CDLL('libc.so.6')
    libc.getifaddrs.restype = ctypes.c_int
    ifaddr_p = ctypes.pointer(Ifaddrs())
    libc.getifaddrs(ctypes.pointer((ifaddr_p)))
    interfaces: Dict[str, Any] = dict()
    head = ifaddr_p
    while ifaddr_p:
        tmp: Dict[str, Any] = dict()
        iface: str = ifaddr_p.contents.ifa_name.decode()
        if iface not in interfaces.keys():
            interfaces[iface] = []
        tmp['flags'] = ifaddr_p.contents.ifa_flags
        sa_p = ifaddr_p.contents.ifa_addr
        if sa_p:
            family = sa_p.contents.Sockaddr.sa_family
            if family in [socket.AF_INET, socket.AF_INET6]:
                tmp['family'] = family
                if family == socket.AF_INET:
                    tmp['port'] = sa_p.contents.Sockaddr_in.sin_port
                    tmp['addr'] = str(ipaddress.ip_address(socket.htonl(sa_p.contents.Sockaddr_in.sin_addr)))
                if family == socket.AF_INET6:
                    s6 = bytes(sa_p.contents.Sockaddr_in6.sin6_addr.s6_addr)
                    tmp['addr'] = str(ipaddress.IPv6Address(s6))
                interfaces[iface].append(tmp)
        ifaddr_p = ifaddr_p.contents.ifa_next
    libc.freeifaddrs(head)
    return interfaces


def get_ip_addrs(family: Optional[int] = None) -> Dict[str, List[str]]:
    ifaces = dump_interfaces()
    results: Dict[str, List[str]] = {}
    for iface, members in ifaces.items():
        results[iface] = [member['addr'] for member in members if 'addr' in member.keys() and (family is None or member['family'] == family)]
    return results


def get_first_addr(family: Optional[int] = None) -> str:
    addrs = get_ip_addrs(family)
    addrs.pop(get_loopback_interface(), None)
    for iface in addrs.keys():
        try:
            first_addr = addrs[iface][0]
            return first_addr
        except IndexError:
            pass
    raise SystemExit('No ip address found.')
