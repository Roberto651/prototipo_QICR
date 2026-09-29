import networkx as nx
from typing import List
from src.domain.exceptions import KnowledgeGraphNodeError

class KnowledgeGraph:
    def __init__(self):
        self.graph = nx.DiGraph()
        self._cache = {}

    def add_inclusion(self, parent: str, children: List[str]) -> None:
        for child in children:
            self.graph.add_edge(parent, child)
        self._cache.clear()

    def get_atomic_nodes(self, node: str) -> List[str]:
        """Retorna os subgrupos não divisíveis (folhas) de um grupo abstrato."""
        if node in self._cache:
            return self._cache[node]

        if node not in self.graph:
            # Assumimos que, se não estiver no grafo, ele próprio é um nó atômico.
            self._cache[node] = [node]
            return [node]
        
        descendants = nx.descendants(self.graph, node)
        leaves = [n for n in descendants if self.graph.out_degree(n) == 0]
        
        result = leaves if leaves else [node]
        self._cache[node] = result
        return result
