import logging
import networkx as nx
from typing import List, Dict, Tuple
from src.domain.models import Intent
from src.core.kg import KnowledgeGraph

logger = logging.getLogger(__name__)

class QICREngine:
    def __init__(self, kg: KnowledgeGraph):
        self.kg = kg
        self.max_bandwidth = 100.0  # Mbps
        self.min_latency = 5.0      # ms
        self.max_packet_loss = 1.0  # %
        self.available_bandwidth = self.max_bandwidth

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
            return ["FW"] # Heurística padrão

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

    def resolve_qos_intra_conflicts(self, intents: List[Intent]) -> List[Intent]:
        logger.info("=== Iniciando Detecção de Conflitos Intra-Intent QoS (III.B) ===")
        valid_intents = []
        for intent in intents:
            conflict = False
            # Violation of System Thresholds
            if intent.latency is not None and intent.latency < self.min_latency:
                logger.warning(f"[Intra-Intent] Latency {intent.latency} below system limit ({self.min_latency}) for {intent.src}->{intent.dst}")
                conflict = True
            # Resource overcommitment
            if intent.bandwidth is not None and intent.bandwidth > self.max_bandwidth:
                logger.warning(f"[Intra-Intent] Bandwidth {intent.bandwidth} exceeds system capacity ({self.max_bandwidth}) for {intent.src}->{intent.dst}")
                conflict = True
            # Incompatible Service Expectations
            if intent.latency is not None and intent.packet_loss is not None:
                if intent.latency < 10 and intent.packet_loss > self.max_packet_loss:
                    logger.warning(f"[Intra-Intent] Incompatible expectations: ultra-low latency mas packet loss > {self.max_packet_loss} for {intent.src}->{intent.dst}")
                    conflict = True
                    
            if not conflict:
                valid_intents.append(intent)
            else:
                logger.warning(f"Intent {intent.src}->{intent.dst} rejected due to intra-intent conflict.")
        return valid_intents

    def resolve_qos_inter_conflicts(self, intents: List[Intent]) -> List[Intent]:
        logger.info("=== Iniciando Resolução de Conflitos Inter-Intent QoS (III.C) ===")
        qos_intents = [i for i in intents if i.bandwidth is not None]
        no_qos_intents = [i for i in intents if i.bandwidth is None]
        
        total_bw_requested = sum(i.bandwidth for i in qos_intents)
        if total_bw_requested <= self.max_bandwidth:
            logger.info("Nenhum conflito Inter-Intent de recursos detectado.")
            return intents

        logger.warning(f"[Inter-Intent] Cross-Intent Resource Contention: Cumulative BW ({total_bw_requested}) exceeds capacity ({self.max_bandwidth}). Resolving...")
        
        # Conflict Resolution Model
        resolved_qos_intents = []
        
        # Definir quais são de alta prioridade (ex: priority >= 80)
        high_prio_threshold = 80
        high_priority = [i for i in qos_intents if (i.priority or 0) >= high_prio_threshold]
        normal_priority = [i for i in qos_intents if (i.priority or 0) < high_prio_threshold]
        
        # Priority-Based Allocation (up to 40% of bandwidth)
        hp_limit = 0.4 * self.max_bandwidth
        hp_used = 0.0
        
        # Sort high priority by priority descending
        high_priority.sort(key=lambda x: x.priority or 0, reverse=True)
        
        for intent in high_priority:
            if hp_used + intent.bandwidth <= hp_limit:
                hp_used += intent.bandwidth
                resolved_qos_intents.append(intent)
            else:
                normal_priority.append(intent)
                
        # Weighted Fair Sharing for the rest
        remaining_bw = self.max_bandwidth - hp_used
        total_weight = sum((i.priority or 1) for i in normal_priority)
        
        for intent in normal_priority:
            weight = (intent.priority or 1)
            share = remaining_bw * (weight / total_weight) if total_weight > 0 else 0
            
            allocated_bw = min(intent.bandwidth, share)
            if allocated_bw < intent.bandwidth:
                logger.info(f"SLA Relaxation for {intent.src}->{intent.dst}: Bandwidth reduced from {intent.bandwidth} to {allocated_bw:.2f} due to Weighted Fair Sharing.")
                intent.bandwidth = round(allocated_bw, 2)
            resolved_qos_intents.append(intent)
            
        logger.info("=== Fim da Resolução Inter-Intent QoS ===")
        return resolved_qos_intents + no_qos_intents

    def resolve_conflicts(self, intents: List[Intent]) -> List[Intent]:
        logger.info("Resolvendo Conflitos Intra-Intent QoS...")
        intra_resolved = self.resolve_qos_intra_conflicts(intents)
        
        logger.info("Resolvendo Conflitos Estruturais/SFC...")
        structural_resolved = self.resolve_structural_conflicts(intra_resolved)
        
        logger.info("Resolvendo Conflitos Inter-Intent QoS...")
        return self.resolve_qos_inter_conflicts(structural_resolved)

    def resolve_structural_conflicts(self, intents: List[Intent]) -> List[Intent]:
        logger.info("=== Iniciando Resolução de Conflitos Estruturais ===")
        
        # 1. Identificação Inicial de Conflitos
        conflicting_indices = set()
        for i in range(len(intents)):
            for j in range(i + 1, len(intents)):
                if self.check_conflict(intents[i], intents[j]):
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
                            deny=intent.deny.copy(),
                            bandwidth=intent.bandwidth,
                            latency=intent.latency,
                            packet_loss=intent.packet_loss,
                            priority=intent.priority
                        )
                    )
        
        resolved_intents = []
        
        # 3. Combinação de fluxos sobrepostos
        for (src, dst), intent_list in atomic_intents.items():
            if len(intent_list) == 1:
                resolved_intents.append(intent_list[0])
                continue
            
            combined_filters = set()
            combined_permit = set()
            combined_deny = set()
            combined_bandwidth = None
            combined_latency = None
            combined_packet_loss = None
            combined_priority = None
            
            for intent in intent_list:
                combined_filters.update(intent.filters)
                combined_permit.update(intent.permit)
                combined_deny.update(intent.deny)
                
                if intent.bandwidth is not None:
                    combined_bandwidth = max(combined_bandwidth, intent.bandwidth) if combined_bandwidth is not None else intent.bandwidth
                if intent.latency is not None:
                    combined_latency = min(combined_latency, intent.latency) if combined_latency is not None else intent.latency
                if intent.packet_loss is not None:
                    combined_packet_loss = min(combined_packet_loss, intent.packet_loss) if combined_packet_loss is not None else intent.packet_loss
                if intent.priority is not None:
                    combined_priority = max(combined_priority, intent.priority) if combined_priority is not None else intent.priority
            
            combined_sfc = self._combine_sfcs(intent_list)
            
            final_filters = combined_filters - combined_deny
            final_permit = combined_permit - combined_deny


            resolved_intents.append(
                Intent(
                    src=src, 
                    dst=dst, 
                    src_type="endpoint",
                    dst_type="endpoint",
                    filters=final_filters, 
                    sfc=combined_sfc, 
                    permit=final_permit, 
                    deny=combined_deny,
                    bandwidth=combined_bandwidth,
                    latency=combined_latency,
                    packet_loss=combined_packet_loss,
                    priority=combined_priority
                )
            )

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
