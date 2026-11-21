
from ipaddress import IPv4Network

from models import FirewallConfig, Rule, Condition, Action, PortRange 
from collections.abc import Iterable, Iterator
import re
import shlex

def parse_config_from_file(filename: str) -> FirewallConfig:
    """Read the firewall config from file and pare it into a FirewallConfig object"""
    rules: list[Rule] = []
    address_lists: dict[str, set[IPv4Network]] = {}
    interface_lists: dict[str, set[str]] = {}
    interface_ips: dict[str, set[IPv4Network]] = {}
    
    with open(filename, "r", encoding="utf-8") as f:
        continuated_lines = iter_continued_lines(f)
        lines_with_sections = iter_sections(continuated_lines)

        for section, line in lines_with_sections:
            tokens = shlex.split(line)
            line_dict: dict[str, str] = {}

            for token in tokens:
                x = token.split("=", 1)
                if len(x) > 1:
                    key = x[0]
                    value = x[1]
                    line_dict[key] = value
            
            

            
    return FirewallConfig(
        rules,
        address_lists =   {k: frozenset(v) for k,v in address_lists.items()},
        interface_lists = {k: frozenset(v) for k,v in interface_lists.items()},
        interface_ips =   {k: frozenset(v) for k,v in interface_ips.items()},
    )


def iter_sections(lines: Iterable[str]) -> Iterator[tuple[str, str]]:
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




def iter_continued_lines(lines: Iterable[str]) -> Iterator[str]:
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

         





