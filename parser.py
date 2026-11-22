
from ipaddress import IPv4Network
from models import FirewallConfig, Rule, Condition, Action, PortRange 
from collections.abc import Callable, Iterable, Iterator
import re
import shlex
from collections import defaultdict
from typing import Any
from ipaddress import IPv4Address,summarize_address_range

def parse_config_from_file(filename: str) -> FirewallConfig:
    """Parse a Mikrotik firewall export file into a FirewallConfig object
    Supports the following configuration sections: 
        - /ip/firewall/filter
        - /ip/firewall/address-list
        - /interface/list
        - /interface/list/member
        - /ip/address

    Args: 
        filename: path to exported configuration file.

    Reurns:
        Strucutred representaion of filter rules, interfaces, address and interface lists
    """
    rules: list[Rule] = []
    address_lists: defaultdict[str, set[IPv4Network]] = defaultdict(set)
    interface_lists: dict[str, set[str]] = defaultdict(set)
    interface_ips: dict[str, set[IPv4Network]] = defaultdict(set)
    
    with open(filename, "r", encoding="utf-8") as f:

        continuated_lines = _iter_continued_lines(f)
        lines_with_sections = _iter_sections(continuated_lines)
        
        rule_id: int = 0
        
        for section, line in lines_with_sections:
            params = _parse_params(line)
            
            match section:
                case "/ip/firewall/filter":
                    rule = _parse_rule(rule_id, params)
                    rules.append(rule)
                    rule_id += 1

                case "/ip/firewall/address-list":
                    name, ip = _parse_address_list(params)
                    address_lists[name].add(ip)
                
                case "/interface/list":
                    raise NotImplementedError
                case "/interface/list/member":
                    raise NotImplementedError

                case "/ip/address":
                    iface, ip = _parse_interface_ips(params)
                    interface_ips[iface].add(ip)
            
    return FirewallConfig(
        rules,
        address_lists =   {k: frozenset(v) for k,v in address_lists.items()},
        interface_lists = {k: frozenset(v) for k,v in interface_lists.items()},
        interface_ips =   {k: frozenset(v) for k,v in interface_ips.items()},
    )


def _parse_params(line: str) -> dict[str, str]:
    """Parse a single command line into key-value pairs.
    Example: 
        >>> _parse_params('add chain=input protocol=tcp dst-port=22 comment="SSH access"')
        {'chain': 'input', 'protocol': 'tcp', 'dst-port': '22', 'comment': 'SSH access'}
    """
    params: dict[str, str] = {}
    tokens = shlex.split(line)
    for token in tokens:
        key, sep, value = token.partition("=")
        if sep:
            params[key] = value
    return params



def _parse_address(val: str) -> frozenset[IPv4Network]:
    """ Parse address string into frozenset of IPv4Network objects.
        Supports combination of comma separated IPs, CIDR subnets and IP ranges.

        Example:
            >>> _parse_address("10.0.0.1,192.168.1.0/24,172.16.0.10-172.16.0.11")
            frozenset({IPv4Network('10.0.0.1/32'), IPv4Network('192.168.1.0/24'), IPv4Network('172.16.0.10/31')})
    """

    result: set[IPv4Network] = set() 
   
    for token in val.split(","):
        start, sep, end = token.partition("-")
        if sep:
            result.update(summarize_address_range(IPv4Address(start), IPv4Address(end)))
        else:
            result.add(IPv4Network(start, strict=False))
    return frozenset(result)


def _parse_portrange(val: str) -> frozenset[PortRange]:
    """ Parse portrange string into frozenset of PortRnage objects.
        Supports combination of comma separated Ports and Port ranges. (Port number only.)

        Example
        >>> _parse_address("22,25-27")
        frozenset({PortRange(22,22), PortRange(25,27)})
    """

    result: set[PortRange] = set()
    
    for token in val.split(","):
        start, sep, end = token.partition("-")
        if sep:
            result.add(PortRange(int(start), int(end)))
        else:
            result.add(PortRange.from_single(int(start)))
    return frozenset(result)

    

def _parse_rule(rule_id: int, params: dict[str, str]) -> Rule:
    """ Construct Rule object from from firewall filter rule paramteters."""

    def condition(key: str, parse: Callable[[str], Any] = str) -> Condition[Any] | None:
        if not (v := params.get(key)):
            return None
        return Condition(parse(v.removeprefix("!")), v.startswith("!"))

    return Rule(
            id = rule_id,
            chain = params["chain"],
            action = Action(params.get("action", "accept")),
            jump_target = params.get("jump-target"), 
            disabled = params.get("disabled", "no").lower() in ("yes", "true"),
            comment = params.get("comment"),
            
            protocol = condition("protocol"),
            
            src_address = condition("src-address", _parse_address),
            dst_address = condition("dst-address", _parse_address),

            src_address_list = condition("src-address-list"),
            dst_address_list = condition("dst-address-list"),

            port = condition("port", _parse_portrange),
            src_port = condition("src-port", _parse_portrange),
            dst_port = condition("dst-port", _parse_portrange),

            in_interface = condition("in-interface"),
            out_interface = condition("out-interface"),

            in_interface_list = condition("in-interface-list"),
            out_interface_list = condition("out-interface-list")
        )


def _parse_address_list(params: dict[str, str]) -> tuple[str, IPv4Network]:
    raise NotImplementedError

def _parse_interface_ips(params: dict[str, str]) -> tuple[str, IPv4Network]:
    raise NotImplementedError



def _iter_sections(lines: Iterable[str]) -> Iterator[tuple[str, str]]:
    """ Yield (section, line) pairs from Mikrotik configuration lines.
        
        Used as a generator function to iterate over lines of sections. 
        Section identifiers are lines started with "/".
        Skips empty lines and comments.

        Example:
            >>> lines = ["# comment", "/ip firewall filter", "add chain=input"]
            >>> for section, line in _iter_sections(lines):
            ...     print(section, line)
            /ip/firewall/filter add chain=input
    """

    current_section: str = ""

    for line in lines:
        if not line or line.startswith("#"):
            continue
        if line.startswith("/"):
            # current_section = "/".join(line.split().strip("/"))
            current_section = "/" + "/".join(filter(None, re.split(r"[\s/]+", line))).lstrip("/")
            continue
        if not current_section:
            continue

        yield current_section, line




def _iter_continued_lines(lines: Iterable[str]) -> Iterator[str]:
    r"""Yield logical lines by joining backslash-continuated logical lines.
    Used as a generator function to iterate over multi-line commands ending with "\".

    Example:
        >>> raw = [
       ...     "add chain=input \\",
       ...     "    protocol=tcp \\",
       ...     "    action=accept",
       ... ]
       >>> for line in _iter_continued_lines(raw):
           ...     print(line)
       add chain=input protocol=tcp action=accept 
    """

    buf: list[str] = []

    for raw_lines in lines:
        
        # remove trailing newlines
        line = raw_lines.rstrip("\n\r")
        
        # remove leading spaces (indentations) from continious lines
        line = line.lstrip()

        # remove trailing "\" characters
        if line.endswith("\\"):
            buf.append(line.removesuffix("\\"))

        # if no trailing "\" its the end of the command
        else:
            buf.append(line)
            yield "".join(buf)
            
            # processing of the next command starts here
            buf.clear()

         





