
from ipaddress import IPv4Network

from models import FirewallConfig, Rule, Condition, Action, PortRange 
from collections.abc import Iterable, Iterator
import re
import shlex
from collections import defaultdict

def parse_config_from_file(filename: str) -> FirewallConfig:
    """Read the firewall config from file and pare it into a FirewallConfig object"""
    rules: list[Rule] = []
    address_lists: defaultdict[str, set[IPv4Network]] = defaultdict(set)
    interface_lists: dict[str, set[str]] = defaultdict(set)
    interface_ips: dict[str, set[IPv4Network]] = defaultdict(set)
    
    with open(filename, "r", encoding="utf-8") as f:

        continuated_lines = _iter_continued_lines(f)
        lines_with_sections = _iter_sections(continuated_lines)

        for section, line in lines_with_sections:
            params = _parse_params(line)
            
            match section:
                case "/ip/firewall/filter":
                    rule = _parse_rule(params)
                    rules.append(rule)
                
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
    params: dict[str, str] = {}
    tokens = shlex.split(line)
    for token in tokens:
        key, sep, value = token.partition("=")
        if sep:
            params[key] = value
    return params

def _parse_rule(params: dict[str, str]) -> Rule:
    raise NotImplementedError

def _parse_address_list(params: dict[str, str]) -> tuple[str, IPv4Network]:
    raise NotImplementedError

def _parse_interface_ips(params: dict[str, str]) -> tuple[str, IPv4Network]:
    raise NotImplementedError



def _iter_sections(lines: Iterable[str]) -> Iterator[tuple[str, str]]:
    """
        Generator function to iterate over lines of sections. Section identifiers are lines started with "/".
        E.g /ip/firewall
        Yield the current section and current line.
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
    """
       Generator function to iterate over backslash-continuated lines (logical lines).
       Multiple physical lines separated with trailing "\" characters are considered one logical unit.
       E.g. 
       
       Command starts here \
           and contuinuses here with some indentation \
           commnd ends here
       
       This section is considered one logical line.
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

         





