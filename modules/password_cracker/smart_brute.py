import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from core.greedy_engine import GreedyEngine

class SmartPasswordPrioritizer:
    def __init__(self, user_context=None):
        self.user_context = user_context or {}
        
        def score_password(pwd):
            score = 0
            pwd_lower = pwd.lower()
            
            # Heuristic 1: Contains user info
            if self.user_context.get("name", "").lower() in pwd_lower:
                score += 50
            if str(self.user_context.get("year", "")) in pwd_lower:
                score += 30
                
            # Heuristic 2: Common patterns
            if "123" in pwd_lower: score += 10
            if "!" in pwd_lower: score += 5
            
            # Heuristic 3: Length
            if len(pwd) >= 8: score += 5
            return score
            
        self.greedy = GreedyEngine(score_password)

    def rank_passwords(self, passwords):
        print(f"\n[*] Ranking {len(passwords)} passwords using greedy heuristic...")
        ranked = self.greedy.sort_candidates(passwords)
        print("[+] Top 5 Candidates to try first:")
        for r in ranked[:5]:
            print(f"  - {r}")
        return ranked
