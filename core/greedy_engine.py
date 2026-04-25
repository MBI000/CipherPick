class GreedyEngine:
    def __init__(self, scoring_func):
        self.scoring_func = scoring_func

    def select_best(self, candidates):
        if not candidates: return None
        return max(candidates, key=self.scoring_func)

    def sort_candidates(self, candidates):
        return sorted(candidates, key=self.scoring_func, reverse=True)

    def path_search(self, start_state, expand_func, goal_func, max_steps=100):
        current = start_state
        path = [current]
        for _ in range(max_steps):
            if goal_func(current): return path
            candidates = expand_func(current)
            if not candidates: break
            current = self.select_best(candidates)
            path.append(current)
        return path
