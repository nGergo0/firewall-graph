# MikroTik Firewall graph

> **Status:** Work in Progress

## Concept

This project aims to represent MikroTik firewall rules as a graph and explore possibilities of static graph analysis, visualization, and packet-tracing simulation.

### Firewall Execution Model
- A firewall configuration consists of an ordered list of individual rules grouped into chains.
- There are 3 built-in chains (`input`, `forward`, `output`). The initial entry chain is determined by the packet's routing context.
- Packets traverse the rules sequentially, attempting to match each rule's conditions.
- **On match:** The rule's corresponding action is executed (e.g. `accept`, `drop`, `jump`, `return`).
- **On no match:** Evaluation continues to the next rule in the current chain. If the end of the chain is reached without a match, built-in chains defaults to `accept`, custom chains perform implicit `return`.

### Graph Representation
To model this behavior, the ruleset is represented as an **Interprocedural Control Flow Graph**.

- **Rule Nodes:** Every firewall rule is represented as a node with 2 outgoing edges: `MATCH` and `NO-MATCH`.
- **`NO-MATCH` Edges:** Point to the next rule within the same chain. At the end of the chain this edge points to `RETURN` node for custom chains or `ACCEPT` node for  built-in chains.
- **`MATCH` Edges:** Point to the target node determined by the rule's action (`terminal`, `entry`, or `return` nodes).
- **Helper Nodes** *(do not contain rules)*:
  - **Terminal Nodes:** One for each terminal action (`ACCEPT`, `DROP`, `REJECT`), with no outgoing edges.
  - **Entry Nodes:** One for each chain representing its entry point (e.g. `ENTRY:input`), having a single `NEXT` outgoing edge pointing to the first rule in that chain.
  - **Return Node:** A `RETURN` node with no outgoing edges.

### Handling `RETURN` Actions
The `RETURN` node cannot have static outgoing edges because its target is context-dependent—a custom chain can be invoked via `jump` from multiple different rules across different chains (analogous to function calls in programming languages).

For this reason, an Interprocedural Control Flow Graph is required. During packet simulation, a **return stack** is maintained to track jump origins so that when a `RETURN` action is encountered, execution resumes at the correct rule in the caller chain.