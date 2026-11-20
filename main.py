from parser import parse_config_from_file
from control_flow_graph import build_cfg 
from simulator import trace_packet
from graph_visualizer import plot_graph

def main():
    config = parse_config_from_file("firewall.rsc")
    cfg = build_cfg(config.rules)
    
if __name__ == "__main__":
    main()

