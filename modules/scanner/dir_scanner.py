import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from core.recursion_engine import RecursionEngine

class DirectoryScanner:
    def __init__(self, root_dir, max_depth=5):
        self.root_dir = root_dir
        self.engine = RecursionEngine(limit=max_depth)
        self.suspicious_exts = {'.key', '.pem', '.env', '.config', '.bak'}

    def expand(self, state):
        current_path = state
        children = []
        try:
            if os.path.isdir(current_path):
                for item in os.listdir(current_path):
                    children.append(os.path.join(current_path, item))
        except PermissionError:
            pass
        return children

    def scan(self):
        print(f"\n[*] Recursively scanning directory: {self.root_dir}")
        all_files = self.engine.traverse(self.root_dir, self.expand)
        
        suspicious = []
        for f in all_files:
            if os.path.isfile(f):
                _, ext = os.path.splitext(f)
                if ext in self.suspicious_exts or os.path.basename(f).startswith('.'):
                    suspicious.append(f)
                    
        print(f"[+] Found {len(suspicious)} suspicious/hidden files.")
        for s in suspicious[:10]:
            print(f"  - {s}")
        return suspicious
