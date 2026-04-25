import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from core.greedy_engine import GreedyEngine

class TargetPrioritizer:
    def __init__(self):
        def score_target(target):
            # target = {"domain": str, "activity": int, "exposure": int}
            return (target['exposure'] * 2) + target['activity']
            
        self.greedy = GreedyEngine(score_target)

    def rank_targets(self, targets):
        print(f"\n[*] Ranking OSINT targets based on Activity and Exposure Risk...")
        ranked = self.greedy.sort_candidates(targets)
        for i, t in enumerate(ranked, 1):
            print(f"  {i}. {t['domain']} (Score: {self.greedy.scoring_func(t)})")
        return ranked
