from __future__ import annotations
from dataclasses import dataclass
from enum import StrEnum, auto
from ipaddress import IPv4Address, IPv4Network, IPv6Network, IPv4Interface
from typing import Callable, Any
import operator

@dataclass(frozen=True)
class Condition[T]:
    """Generic wrapper class to represent conditions.
       In Mikrotik rules almost every condition can contain negation (with "!" e.g. protocol=!tcp) 
    """
    value: T
    negated: bool = False
    
    def matches(self, actual: Any, comparator: Callable[[Any, T], bool] = operator.eq):
        is_match = comparator(actual, self.value)
        return not is_match if self.negated else is_match

class Action(StrEnum):
    # terminal actions
    ACCEPT = auto()
    DROP = auto()
    REJECT = auto()
    
    # control flow
    JUMP = auto()
    RETURN = auto()
    
    # other ...


@dataclass(frozen=True)
class PortRange:
    start: int
    end: int
    
    # This allows the use of "in" operator e.g. 22 in port_range
    def __contains__(self, port: int) -> bool:
        return self.start <= port <= self.end
    
    @classmethod
    def from_single(cls, port: int) -> "PortRange":
        return cls(port, port)


@dataclass(frozen=True)
class Rule:
    id: int
    chain: str
    action: Action
    jump_target: str | None = None
    disabled: bool = False
    comment: str | None = None 

    protocol: Condition[str] | None = None
   
    # A set is used because this can represent either a single IP or a collection of subnets. 
    src_address: Condition[frozenset[IPv4Network]] | None = None
    dst_address: Condition[frozenset[IPv4Network]] | None = None
    
    src_address_list: Condition[str] | None = None
    dst_address_list: Condition[str] | None = None
    
    port:     Condition[frozenset[PortRange]] | None = None
    src_port: Condition[frozenset[PortRange]] | None = None
    dst_port: Condition[frozenset[PortRange]] | None = None

    in_interface:  Condition[str] | None = None
    out_interface: Condition[str] | None = None
    
    in_interface_list:  Condition[str] | None = None
    out_interface_list: Condition[str] | None = None
    # other conditions (if needed)

    def matches(self, packet: Packet, in_interface: str | None, out_interface: str | None, config: FirewallConfig) -> bool:

        def _check[T](actual: Any, condition: Condition[T] | None, comparator: Callable[[Any, T], bool] = operator.eq) -> bool: 
            if condition is None:
                return True
            if actual is None:
                return False
            return condition.matches(actual, comparator)

        if not _check(packet.protocol, self.protocol):
            return False
        if not _check(packet.src_address, self.src_address,      lambda ip, networks: any(ip in nw for nw in networks)):
            return False
        if not _check(packet.dst_address, self.dst_address,      lambda ip, networks: any(ip in nw for nw in networks)):
            return False
        
        if not _check(packet.src_address, self.src_address_list, lambda ip, add_list: any(ip in nw for nw in config.address_lists.get(add_list, frozenset()))):
            return False
        if not _check(packet.dst_address, self.dst_address_list, lambda ip, add_list: any(ip in nw for nw in config.address_lists.get(add_list, frozenset()))):
            return False
       
        
        if self.port is not None:

            src_match = _check(packet.src_port, self.port,      lambda port, p_ranges: any(port in p_range for p_range in p_ranges))
            dst_match = _check(packet.dst_port, self.port,      lambda port, p_ranges: any(port in p_range for p_range in p_ranges))

            port_matched = (src_match and dst_match) if self.port.negated else (src_match or dst_match)
            if not port_matched:
                return False

        if not _check(packet.src_port, self.src_port,           lambda port, p_ranges: any(port in p_range for p_range in p_ranges)):
            return False
        if not _check(packet.dst_port, self.dst_port,           lambda port, p_ranges: any(port in p_range for p_range in p_ranges)):
            return False

        if not _check(in_interface, self.in_interface):
            return False
        if not _check(out_interface, self.out_interface):
            return False
        if not _check(in_interface, self.in_interface_list,     lambda iface, iface_list: iface in config.interface_lists.get(iface_list, frozenset())):
            return False
        if not _check(out_interface, self.out_interface_list,   lambda iface, iface_list: iface in config.interface_lists.get(iface_list, frozenset())):
            return False

        return True


@dataclass(frozen=True)
class Packet:
    protocol: str
    src_address: IPv4Address
    dst_address: IPv4Address
    src_port: int | None
    dst_port: int | None

@dataclass(frozen=True)
class FirewallConfig:
    # /ip/firewall/filter
    rules: list[Rule]
    
    # /ip/firewall/address-list
    address_lists: dict[str, frozenset[IPv4Network]]
    
    # /interface/list and /interface/list/member
    interface_lists: dict[str, frozenset[str]]
    
    # /ip/address
    interface_ips: dict[str, frozenset[IPv4Interface]]


