import time
import random
import tracemalloc
from src.core.kg import KnowledgeGraph
from src.core.engine import QICREngine
from src.domain.models import Intent

def run_scalability_test():
    print("=== 1. Teste de Escalabilidade Linear (Sem Conflitos) ===")
    print("Avalia o tempo de processamento conforme o numero de intencoes aumenta.")
    print(f"{'Intenções':<12} | {'Tempo (s)':<12} | {'Memória Pico (KB)':<20} | {'Output Regras'}")
    
    kg = KnowledgeGraph()
    # Topologia plana para evitar sobreposição nesse teste
    endpoints = [f"End_{i}" for i in range(1, 1001)] 
    
    for num_intents in [10, 50, 100, 200, 500]:
        engine = QICREngine(kg)
        intents = []
        for _ in range(num_intents):
            src = random.choice(endpoints)
            dst = random.choice(endpoints)
            while src == dst:
                dst = random.choice(endpoints)
            
            intents.append(Intent(
                src=src, dst=dst, 
                filters={80}, sfc=["FW"], 
                permit={80}, deny=set()
            ))
            
        tracemalloc.start()
        start_time = time.perf_counter()
        
        resolved = engine.resolve_conflicts(intents)
        
        end_time = time.perf_counter()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        print(f"{num_intents:<12} | {end_time - start_time:<12.4f} | {peak / 1024:<20.2f} | {len(resolved)}")
    print("\n")

def run_conflict_complexity_test():
    print("=== 2. Teste de Complexidade SFC (Ordenação Topológica com Conflitos) ===")
    print("Avalia o peso computacional de resolver paradoxos na MESMA rota.")
    print(f"{'Conflitos':<12} | {'Tempo (s)':<12} | {'Memória Pico (KB)':<20} | {'Output Regras'}")
    
    kg = KnowledgeGraph()
    src, dst = "A1", "Web"
    
    for num_conflicts in [2, 5, 10, 15, 20]:
        engine = QICREngine(kg)
        intents = []
        middleboxes = ["FW", "IDS", "DDoS", "LB", "WAF"]
        
        for _ in range(num_conflicts):
            # Cria cadeias caóticas para o algoritmo resolver
            random.shuffle(middleboxes)
            sfc_chain = middleboxes[:random.randint(1, 4)]
            
            intents.append(Intent(
                src=src, dst=dst, 
                filters={80}, sfc=sfc_chain, 
                permit={80}, deny=set()
            ))
            
        tracemalloc.start()
        start_time = time.perf_counter()
        
        resolved = engine.resolve_conflicts(intents)
        
        end_time = time.perf_counter()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        print(f"{num_conflicts:<12} | {end_time - start_time:<12.4f} | {peak / 1024:<20.2f} | {len(resolved)}")
    print("\n")

def run_knowledge_graph_test():
    print("=== 3. Teste de Resolução do Grafo de Conhecimento (Topologia Hierárquica) ===")
    print("Avalia o tempo e memória para desmembrar grupos abstratos profundos em nós atômicos.")
    print(f"{'Profundidade':<12} | {'Nós Totais':<12} | {'Tempo (s)':<12} | {'Memória Pico (KB)':<20} | {'Folhas (IPs)'}")
    
    # Configurações de teste: (Profundidade da Árvore, Ramificações por Nó)
    # Exemplo: (3, 5) -> 1 Raiz -> 5 Filiais -> 25 Setores -> 125 IPs
    configs = [
        (3, 5),  # Rede Pequena (125 dispositivos finais)
        (4, 5),  # Rede Média (625 dispositivos finais)
        (5, 5),  # Rede Grande (3.125 dispositivos finais)
        (6, 4),  # Árvore mais profunda (4.096 dispositivos finais)
        (7, 3),  # Extrema profundidade (2.187 dispositivos finais, muitos níveis gerenciais)
    ]
    
    for depth, branching_factor in configs:
        kg = KnowledgeGraph()
        
        # Função recursiva para popular o grafo automaticamente
        def build_tree(current_node, current_depth):
            if current_depth == depth:
                return  # Chegamos no dispositivo final (IP), não cria mais filhos
            
            children = [f"{current_node}_L{current_depth + 1}_{i}" for i in range(branching_factor)]
            kg.add_inclusion(current_node, children)
            
            for child in children:
                build_tree(child, current_depth + 1)
                
        root_name = "Empresa_Matriz"
        
        # 1. Popula o grafo de conhecimento antes de iniciar o cronômetro
        build_tree(root_name, 0)
        
        # Opcional: Conta quantos nós o networkx gerou no total
        total_nodes = len(kg.graph.nodes) if hasattr(kg, 'graph') else "N/A"
        
        # 2. Inicia o teste de desempenho
        tracemalloc.start()
        start_time = time.perf_counter()
        
        # 3. O desafio: Desmembrar a matriz inteira até achar o último IP
        atomic_nodes = kg.get_atomic_nodes(root_name)
        
        end_time = time.perf_counter()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        print(f"{depth:<12} | {total_nodes:<12} | {end_time - start_time:<12.4f} | {peak / 1024:<20.2f} | {len(atomic_nodes)}")
    print("\n")

def run_scalability_with_conflicts_flat_graph():
    print("=== 4. Teste de Escalabilidade com Conflitos (Grafo Plano) ===")
    print("Avalia o tempo de interseção e resolução de políticas sobrepostas em poucos IPs.")
    print(f"{'Intenções':<12} | {'Tempo (s)':<12} | {'Memória Pico (KB)':<20} | {'Output Regras'}")
    
    kg = KnowledgeGraph()
    # Poucos endpoints para forçar cruzamento contínuo e muitos conflitos
    endpoints = ["A1", "A2", "B1", "B2"] 
    middleboxes = ["FW", "IDS", "DDoS", "WAF", "LB"]
    
    for num_intents in [10, 50, 100, 200, 500]:
        engine = QICREngine(kg)
        intents = []
        for _ in range(num_intents):
            src = random.choice(endpoints)
            dst = random.choice(endpoints)
            while src == dst: dst = random.choice(endpoints)
            
            # Gera regras caóticas para forçar o deny-overrides e a ordenação SFC
            permit_ports = set(random.sample([80, 443, 22, 53, 3306], k=random.randint(1, 3)))
            deny_ports = set(random.sample([22, 8080, 80], k=random.randint(0, 2)))
            sfc = random.sample(middleboxes, k=random.randint(1, 3))
            
            intents.append(Intent(src=src, dst=dst, filters=permit_ports, sfc=sfc, permit=permit_ports, deny=deny_ports))
            
        tracemalloc.start()
        start_time = time.perf_counter()
        
        # Como o logger foi configurado no projeto principal, mas aqui queremos console limpo,
        # vamos deixar a resolução rodar (pode haver prints internos dependendo de como o logger foi injetado)
        resolved = engine.resolve_conflicts(intents)
        
        end_time = time.perf_counter()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        print(f"{num_intents:<12} | {end_time - start_time:<12.4f} | {peak / 1024:<20.2f} | {len(resolved)}")
    print("\n")

def run_scalability_with_conflicts_populated_graph():
    print("=== 5. Teste de Escalabilidade com Conflitos (Grafo Populado) ===")
    print("O 'Pior Cenário': Intenções conflitantes aplicadas massivamente sobre grupos hierárquicos.")
    print(f"{'Intenções':<12} | {'Tempo (s)':<12} | {'Memória Pico (KB)':<20} | {'Output Regras'}")
    
    kg = KnowledgeGraph()
    # Criaremos uma árvore média para evitar que o teste demore muitos minutos na banca
    depth, branching = 4, 4 # 1 -> 4 -> 16 -> 64 -> 256 folhas (IPs totais)
    
    def build_tree(current_node, current_depth):
        if current_depth == depth: return
        children = [f"{current_node}_{i}" for i in range(branching)]
        kg.add_inclusion(current_node, children)
        for child in children: build_tree(child, current_depth + 1)
            
    build_tree("Matriz", 0)
    
    # Pegar os dois grupos principais (nível 1) para gerar conflito em massa (cada um afeta 64 IPs)
    grupos_alvo = ["Matriz_0", "Matriz_1", "Matriz_2", "Matriz_3"]
    middleboxes = ["FW", "IDS", "DDoS"]
    
    # Menos intents pois a explosão combinatória é gigante (10 intents = 40.960 combinações avaliadas)
    for num_intents in [5, 10, 25, 50]: 
        engine = QICREngine(kg)
        intents = []
        for _ in range(num_intents):
            src = random.choice(grupos_alvo)
            dst = random.choice(grupos_alvo)
            while src == dst: dst = random.choice(grupos_alvo)
            
            permit_ports = set(random.sample([80, 443, 22], k=random.randint(1, 2)))
            deny_ports = set(random.sample([22, 8080], k=random.randint(0, 1)))
            sfc = random.sample(middleboxes, k=random.randint(1, 2))
            
            intents.append(Intent(src=src, dst=dst, filters=permit_ports, sfc=sfc, permit=permit_ports, deny=deny_ports))
            
        tracemalloc.start()
        start_time = time.perf_counter()
        
        resolved = engine.resolve_conflicts(intents)
        
        end_time = time.perf_counter()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        print(f"{num_intents:<12} | {end_time - start_time:<12.4f} | {peak / 1024:<20.2f} | {len(resolved)}")
    print("\n")

if __name__ == "__main__":
    import logging
    # Silenciar os logs do motor durante o benchmark para o output ficar limpo
    logging.getLogger().setLevel(logging.ERROR) 
    
    print("Iniciando Bateria de Testes de Desempenho para TCC...\n")
    run_scalability_test()
    run_conflict_complexity_test()
    run_knowledge_graph_test()
    run_scalability_with_conflicts_flat_graph()
    run_scalability_with_conflicts_populated_graph()