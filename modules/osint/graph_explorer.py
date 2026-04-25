import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from core.recursion_engine import RecursionEngine

class GraphExplorer:
    def __init__(self, graph_data):
        self.graph_data = graph_data
        self.engine = RecursionEngine(limit=5)

    def expand(self, state):
        return self.graph_data.get(state, [])

    def explore(self, start_node):
        print(f"\n[*] Recursively exploring graph connections starting from: {start_node}")
        nodes = self.engine.traverse(start_node, self.expand)
        print(f"[+] Entity graph traversal discovered {len(nodes)} unique entities:")
        for node in nodes:
            print(f"  - {node}")
        return nodes
