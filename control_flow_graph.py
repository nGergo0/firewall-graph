from typing import Any

import networkx as nx
from models import Rule, Action


def build_cfg(rules: list[Rule]) -> nx.DiGraph:
    """Build a control-flow graph from the firewall rules.
       The NetworkX library is used to represent the graph.
    """
    cfg = nx.DiGraph()
    
    cfg.add_node("RETURN", kind="return")

    cfg.add_node("ACCEPT", kind="terminal")
    cfg.add_node("DROP",   kind="terminal")
    cfg.add_node("REJECT", kind="terminal")


    cfg.add_node("ENTRY:input",   kind="entry")
    cfg.add_node("ENTRY:forward", kind="entry")
    cfg.add_node("ENTRY:output",  kind="entry")

    # {"chain": "last seen node"}
    last_seen: dict[str, Any] = {
        "input": "ENTRY:input",
        "forward": "ENTRY:forward",
        "output": "ENTRY:output",
    }

    for rule in rules:
        if rule.disabled:
            continue
        # in case of new custom chain, create the entry node
        if rule.chain not in last_seen:
            entry_id = f"ENTRY:{rule.chain}"
            cfg.add_node(entry_id, kind = "entry")
            last_seen[rule.chain] = entry_id
        
        current_node = f"rule:{rule.id}"
        # add a new node for the rule
        cfg.add_node(current_node, kind="rule", rule=rule)
        
        # add an edge from the last seen node of the current chain
        prev_node = last_seen[rule.chain]
        kind = "NEXT" if cfg.nodes[prev_node]["kind"] == "entry" else "NO-MATCH"

        cfg.add_edge(prev_node, current_node, kind = kind)
        last_seen[rule.chain] = current_node
    

        match rule.action:
            case Action.ACCEPT:
                cfg.add_edge(current_node, "ACCEPT", kind = "MATCH")
            case Action.DROP: 
                cfg.add_edge(current_node, "DROP",   kind = "MATCH")
            case Action.REJECT:
                cfg.add_edge(current_node, "REJECT", kind = "MATCH")
            case Action.RETURN:
                cfg.add_edge(current_node, "RETURN", kind = "MATCH")

            case Action.JUMP:
                if rule.jump_target is None:
                    raise ValueError(f"Missing jump-target in rule:{rule.id}")

                target_node = f"ENTRY:{rule.jump_target}"
                
                if not cfg.has_node(target_node):
                    cfg.add_node(target_node, kind="entry")
                    last_seen[rule.jump_target] = target_node

                cfg.add_edge(current_node, target_node, kind = "MATCH")
    
    # if NO MATCH at the last rule of a chain, then implicit RETURN in custom chains, and ACCEPT in default chains
    for chain, last_node in last_seen.items():
        kind = "NEXT" if cfg.nodes[last_node]["kind"] == "entry" else "NO-MATCH" 
        target_node = "ACCEPT" if chain in ("input", "forward", "output") else "RETURN"
        cfg.add_edge(last_node, target_node, kind = kind)
    
    return cfg



