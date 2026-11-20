from dataclasses import dataclass
from enum import StrEnum, auto
from ipaddress import IPv4Network, IPv6Network
import networkx as nx
import graphviz

@dataclass(frozen=True)
class Condition[T]:
    """Generic wrapper class to represent conditions.
       In Mikrotik rules almost every condition can contain negation (with "!" e.g. protocol=!tcp) 
    """
    value: T
    negated: bool = False


class Action(StrEnum):
    # terminal cations
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

@dataclass(frozen=True)
class Packet:
    #TODO
    pass

@dataclass(frozen=True)
class FirewallConfig:
    # /ip/firewall/filter
    rules: list[Rule]
    
    # /ip/firewall/address-list
    address_lists: dict[str, frozenset[IPv4Network]]
    
    # /interface/list and /interface/list/member
    interface_lists: dict[str, frozenset[str]]
    
    # /ip/address
    interface_ips: dict[str, frozenset[IPv4Network]]



def parse_config_from_file(filename: str) -> FirewallConfig:
    """Read the firewall config from file and pare it into a FirewallConfig object"""
    # TODO
    raise NotImplementedError


def build_cfg(rules: list[Rule]) -> nx.DiGraph:
    """Build a control-flow graph from the firewall rules.
       The NetworkX library is used to represent the graph.
    """
    # TODO
    raise NotImplementedError

def trace_packet(cfg: nx.DiGraph, config:FirewallConfig, packet: Packet) -> nx.DiGraph:
    """Simulate package processing.
       Traverse the control flow graph with the test package and check at each node whether the corresponding eule matches the packet.
       Finally return the traversed subgraph (path).
    """ 
    # TODO
    raise NotImplementedError


def plot_graph(graph: nx.DiGraph) -> graphviz.DiGraph:
    """Convert a NetworkX grpah to Graphviz graph for visual representaion"""
    # TODO
    raise NotImplementedError



