import networkx as nx
from models import Action, FirewallConfig, Packet, Rule


def trace_packet(cfg: nx.DiGraph, config:FirewallConfig, packet: Packet) -> nx.DiGraph:
    """Simulate package processing.
       Traverse the control flow graph with the test package and check
       at each node whether the corresponding eule matches the packet.
       Finally return the traversed subgraph (path).
    """ 
    # resolve routing: interfaces and default_chain

    DEFAULT_WAN: str = "eth01"
    entry_chain: str = "forward"
    in_interface: str | None = DEFAULT_WAN
    out_interface: str | None = DEFAULT_WAN

    for name, ifaces in config.interface_ips.items():
        for iface in ifaces:
            
            if packet.src_address in iface.network:
                in_interface = name
            if packet.dst_address in iface.network:
                out_interface = name
            
            if packet.src_address == iface.ip:
               entry_chain = "output"
            elif packet.dst_address == iface.ip:
               entry_chain = "input"

    if entry_chain == "input":
        out_interface = None
    elif entry_chain == "output":
        in_interface = None
    

    return_stack: list[str] = []
    visited_edges: list[tuple[str, str]] = []
    current = f"ENTRY:{entry_chain}"

    while True:
        prev = current
        node = cfg.nodes[current]
        outgoing = {data["kind"]: target for _, target, data in cfg.out_edges(current, data=True)}

        match node["kind"]:
            case "entry":
                current = outgoing["NEXT"]
            case "rule":
                rule = node["rule"]
                if rule.matches(packet, in_interface, out_interface, config):
                    current = outgoing["MATCH"]
                    if rule.action == Action.JUMP:
                        return_stack.append(outgoing["NO-MATCH"])
                else:
                    current = outgoing["NO-MATCH"]
            case "return": 
                current = return_stack.pop() if return_stack else "ACCEPT"
                 
            case "terminal":
                break
        if cfg.has_edge(prev, current):
            visited_edges.append((prev, current))

    return cfg.edge_subgraph(visited_edges).copy()
