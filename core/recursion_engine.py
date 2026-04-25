class RecursionEngine:
    def __init__(self, limit=100):
        self.limit = limit

    def dfs(self, state, expand_func, goal_func, depth=0, visited=None):
        if visited is None:
            visited = set()
        if depth >= self.limit: return None
        
        state_key = str(state)
        if state_key in visited: return None
        visited.add(state_key)

        if goal_func(state): return state

        for next_state in expand_func(state):
            res = self.dfs(next_state, expand_func, goal_func, depth + 1, visited)
            if res is not None: return res
        return None

    def backtrack_all(self, state, expand_func, goal_func, depth=0):
        if depth >= self.limit: return []
        if goal_func(state): return [state]
        
        results = []
        for next_state in expand_func(state):
            results.extend(self.backtrack_all(next_state, expand_func, goal_func, depth + 1))
        return results

    def traverse(self, state, expand_func, depth=0, visited=None):
        if visited is None: visited = set()
        if depth >= self.limit: return []
        
        state_key = str(state)
        if state_key in visited: return []
        visited.add(state_key)

        nodes = [state]
        for next_state in expand_func(state):
            nodes.extend(self.traverse(next_state, expand_func, depth + 1, visited))
        return nodes
