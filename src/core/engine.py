import logging
import networkx as nx
from typing import List, Dict, Tuple
from src.domain.models import Intent
from src.core.kg import KnowledgeGraph

logger = logging.getLogger(__name__)

class QICREngine:
    def __init__(self, kg: KnowledgeGraph):
        self.kg = kg

    def _combine_sfcs(self, intents: List[Intent]) -> List[str]:
        # 1. Definir prioridades padrão
        SFC_PRIORITIES = {"DDoS": 100, "FW": 90, "IDS": 80, "IPS": 80, "WAF": 70, "LB": 50}
        
        # Coletar todas as transições originais para calcular aderência
        original_transitions = set()
        unique_nodes = set()
        
        for intent in intents:
            sfc = intent.sfc
            for i in range(len(sfc)):
                unique_nodes.add(sfc[i])
                if i < len(sfc) - 1:
                    original_transitions.add((sfc[i], sfc[i+1]))
        
        if not unique_nodes:
            return []

        # Construir o Grafo DAG
        G = nx.DiGraph()
        G.add_nodes_from(unique_nodes)
        
        for u, v in original_transitions:
            G.add_edge(u, v)
            
        # Se gerar um ciclo, removemos arestas conflitantes de menor prioridade
        while not nx.is_directed_acyclic_graph(G):
            try:
                cycle = nx.find_cycle(G, orientation="original")
                min_edge = None
                min_prio = float('inf')
                for edge in cycle:
                    u, v = edge[0], edge[1]
                    prio = SFC_PRIORITIES.get(v, 0)
                    if prio < min_prio:
                        min_prio = prio
                        min_edge = (u, v)
                G.remove_edge(*min_edge)
                logger.warning(f"Ciclo encontrado na SFC. Aresta {min_edge} removida para garantir ordem topológica.")
            except nx.NetworkXNoCycle:
                break

        # Gerar todas as ordens topológicas
        try:
            all_sorts = list(nx.all_topological_sorts(G))
        except nx.NetworkXUnfeasible:
            all_sorts = [sorted(list(unique_nodes), key=lambda x: SFC_PRIORITIES.get(x, 0), reverse=True)]

        if not all_sorts:
            return sorted(list(unique_nodes), key=lambda x: SFC_PRIORITIES.get(x, 0), reverse=True)

        best_sort = None
        best_priority_score = -1

        for candidate in all_sorts:
            priority_score = 0
            n = len(candidate)
            for i, node in enumerate(candidate):
                priority_score += SFC_PRIORITIES.get(node, 0) * (n - i)
                
            if priority_score > best_priority_score:
                best_priority_score = priority_score
                best_sort = candidate

        return best_sort

    def check_conflict(self, intent1: Intent, intent2: Intent) -> bool:
        """
        Verifica se há intersecção (conflito potencial) nas origens e destinos.
        Compara as folhas (nós atômicos) de ambas as intenções.
        Se compartilharem origem E destino, elas conflitam.
        """
        src1_atomic = set(self.kg.get_atomic_nodes(intent1.src))
        src2_atomic = set(self.kg.get_atomic_nodes(intent2.src))
        
        dst1_atomic = set(self.kg.get_atomic_nodes(intent1.dst))
        dst2_atomic = set(self.kg.get_atomic_nodes(intent2.dst))
        
        same_src = bool(src1_atomic.intersection(src2_atomic))
        same_dst = bool(dst1_atomic.intersection(dst2_atomic))
        
        return same_src and same_dst

    def resolve_conflicts(self, intents: List[Intent]) -> List[Intent]:
        logger.info("=== Iniciando Resolução de Conflitos ===")
        
        # 1. Identificação Inicial de Conflitos
        conflicting_indices = set()
        for i in range(len(intents)):
            for j in range(i + 1, len(intents)):
                if self.check_conflict(intents[i], intents[j]):
                    name_i = intents[i].name if intents[i].name else f"Intent_{intents[i].src}_{intents[i].dst}"
                    name_j = intents[j].name if intents[j].name else f"Intent_{intents[j].src}_{intents[j].dst}"
                    logger.info(f"-> Conflito Macro Identificado: {name_i} vs {name_j}")
                    conflicting_indices.add(i)
                    conflicting_indices.add(j)
                    
        conflicting_intents = [intents[i] for i in conflicting_indices]
        isolated_intents = [intents[i] for i in range(len(intents)) if i not in conflicting_indices]
        
        logger.info(f"Quantitativo Inicial: {len(intents)} intenções totais.")
        logger.info(f"Quantitativo Inicial: {len(conflicting_intents)} intenções identificadas com conflitos potenciais.")
        logger.info(f"Quantitativo Inicial: {len(isolated_intents)} intenções isoladas (origens e destinos independentes).")

        # 2. Decomposição Parcial (somente as conflitantes)
        atomic_intents: Dict[Tuple[str, str], List[Intent]] = {}
        
        for intent in conflicting_intents:
            atomic_srcs = self.kg.get_atomic_nodes(intent.src)
            atomic_dsts = self.kg.get_atomic_nodes(intent.dst)
            
            for src in atomic_srcs:
                for dst in atomic_dsts:
                    pair = (src, dst)
                    if pair not in atomic_intents:
                        atomic_intents[pair] = []
                    atomic_intents[pair].append(
                        Intent(
                            src=src, 
                            dst=dst, 
                            src_type="endpoint",
                            dst_type="endpoint",
                            filters=intent.filters.copy(), 
                            sfc=intent.sfc.copy(), 
                            permit=intent.permit.copy(), 
                            deny=intent.deny.copy()
                        )
                    )
        
        resolved_intents = []
        
        # 3. Combinação de fluxos sobrepostos
        for (src, dst), intent_list in atomic_intents.items():
            if len(intent_list) == 1:
                resolved_intents.append(intent_list[0])
                continue
            logger.info(f"-> Conflito detectado na rota atômica {src} -> {dst}. Intenções envolvidas ({len(intent_list)}):")
            
            combined_filters = set()
            combined_permit = set()
            combined_deny = set()
            
            for idx, intent in enumerate(intent_list, 1):
                logger.info(f"   [Concorrente {idx}] Permitir: {intent.permit} | Bloquear: {intent.deny} | SFC: {intent.sfc}")
                combined_filters.update(intent.filters)
                combined_permit.update(intent.permit)
                combined_deny.update(intent.deny)
            
            combined_sfc = self._combine_sfcs(intent_list)
            
            final_filters = combined_filters - combined_deny
            final_permit = combined_permit - combined_deny

            final_intent = Intent(
                src=src, 
                dst=dst, 
                src_type="endpoint",
                dst_type="endpoint",
                filters=final_filters, 
                sfc=combined_sfc, 
                permit=final_permit, 
                deny=combined_deny
            )
            
            logger.info(f"   [RESULTADO {src} -> {dst}]: A política matemática fundida gerou:\n{final_intent}")
            
            resolved_intents.append(final_intent)

        # 4. Saída e Identificação Final
        final_list = isolated_intents + resolved_intents
        
        remaining_conflicts = 0
        for i in range(len(final_list)):
            for j in range(i + 1, len(final_list)):
                if self.check_conflict(final_list[i], final_list[j]):
                    remaining_conflicts += 1
                    
        logger.info(f"Quantitativo Final: {len(resolved_intents)} intenções atômicas geradas para resolver os conflitos.")
        logger.info(f"Quantitativo Final: {len(isolated_intents)} intenções isoladas mantidas intactas.")
        logger.info(f"Quantitativo Final: Total de {len(final_list)} intenções na rede.")
        
        if remaining_conflicts == 0:
            logger.info("Sucesso: Todos os conflitos foram resolvidos com êxito!")
        else:
            logger.warning(f"Atenção: AINDA EXISTEM {remaining_conflicts} conflitos (deveria ser 0). Revisar algoritmo.")
            
        logger.info("=== Fim da Resolução de Conflitos ===")
        return final_list
