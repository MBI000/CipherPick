import re
import sys
import os

# Add parent to path if needed for standalone testing
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from core.recursion_engine import RecursionEngine
from core.greedy_engine import GreedyEngine

class WebCrawler:
    def __init__(self, start_url, max_depth=3):
        self.start_url = start_url
        self.engine = RecursionEngine(limit=max_depth)
        
        # Greedy engine to prioritize links like admin, login, api
        def link_score(url):
            score = 0
            if 'admin' in url: score += 10
            if 'login' in url: score += 8
            if 'api' in url: score += 5
            return score
        self.greedy = GreedyEngine(link_score)

    def mock_fetch_links(self, url):
        # Mocking link fetching
        mock_map = {
            "http://target.local": ["http://target.local/about", "http://target.local/login", "http://target.local/api/v1"],
            "http://target.local/login": ["http://target.local/admin", "http://target.local/reset"],
            "http://target.local/api/v1": ["http://target.local/api/v1/users", "http://target.local/api/v1/auth"],
            "http://target.local/admin": ["http://target.local/admin/settings"]
        }
        return mock_map.get(url, [])

    def expand(self, state):
        url = state
        links = self.mock_fetch_links(url)
        # Apply greedy sorting so we visit high-priority links first
        return self.greedy.sort_candidates(links)

    def crawl(self):
        print(f"\n[*] Starting recursive crawl from {self.start_url} (Greedy Priority Applied)")
        # traverse all using recursion
        visited_nodes = self.engine.traverse(self.start_url, self.expand)
        print(f"[+] Discovered {len(visited_nodes)} Endpoints:")
        for node in visited_nodes:
            print(f"  - {node}")
        return visited_nodes
