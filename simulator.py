import networkx as nx
from models import FirewallConfig, Packet



def trace_packet(cfg: nx.DiGraph, config:FirewallConfig, packet: Packet) -> nx.DiGraph:
    """Simulate package processing.
       Traverse the control flow graph with the test package and check
       at each node whether the corresponding eule matches the packet.
       Finally return the traversed subgraph (path).
    """ 
    # TODO
    raise NotImplementedError


