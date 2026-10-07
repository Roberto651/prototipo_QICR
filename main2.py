import logging
from src.core.kg import KnowledgeGraph
from src.core.engine import QICREngine
from src.scheduler.calendar import CalendarModule
from src.repository.memory import InMemoryIntentRepository
from src.domain.parser import NileParser

def setup_logger():
    # Configurado para INFO para que os logs de conflito que adicionamos no engine.py sejam impressos!
    logging.basicConfig(
        level=logging.INFO,
        format='%(message)s' # Simplificado para focar na leitura do TCC
    )

def get_robust_kg():
    """
    Constrói um Knowledge Graph hierárquico robusto para a Bateria de Testes.
    Topologia:
    - Matriz
      |-- Financeiro (Fin_PC1, Fin_PC2)
      |-- Engenharia (Eng_PC1, Eng_PC2)
    - Datacenter (Web_Server, DB_Server)
    - Cloud (App_Server, Backup_Server)
    """
    kg = KnowledgeGraph()
    
    kg.add_inclusion("Matriz", ["Financeiro", "Engenharia"])
    kg.add_inclusion("Financeiro", ["Fin_PC1", "Fin_PC2"])
    kg.add_inclusion("Engenharia", ["Eng_PC1", "Eng_PC2"])
    
    kg.add_inclusion("Datacenter", ["Web_Server", "DB_Server"])
    kg.add_inclusion("Cloud", ["App_Server", "Backup_Server"])
    
    return kg

def run_example(title: str, nile_scripts: list):
    print(f"\n\n{'='*100}\n{title}\n{'='*100}")
    
    # Isolando o ambiente para cada teste ter seu próprio banco e motor
    kg = get_robust_kg()
    engine = QICREngine(kg)
    repo = InMemoryIntentRepository()
    calendar = CalendarModule(engine, repo)
    
    for script in nile_scripts:
        calendar.declare_intent(NileParser.parse(script))
        
    calendar.close_time_window()
    
    print(f"\n>>> RESULTADO FINAL NO REPOSITÓRIO (REDE) APÓS RESOLUÇÃO <<<")
    for intent in repo.get_all():
        print(intent)
        print("-" * 50)


if __name__ == "__main__":
    setup_logger()
    
    run_example(
        "EXEMPLO 1: 2 ou mais intenções independentes (Sem conflito)",
        [
            """
            define intent Intencao_A:
              from endpoint('Fin_PC1')
              to endpoint('Web_Server')
              allow traffic('80')
            """,
            """
            define intent Intencao_B:
              from endpoint('Eng_PC1')
              to endpoint('DB_Server')
              allow traffic('3306')
            """
        ]
    )

    run_example(
        "EXEMPLO 2: Conflito Atômico nos Filters (Fusão de Permissões)",
        [
            """
            define intent App_Web_P1:
              from endpoint('Fin_PC1')
              to endpoint('Web_Server')
              allow traffic('80')
            """,
            """
            define intent App_Web_P2:
              from endpoint('Fin_PC1')
              to endpoint('Web_Server')
              allow traffic('443')
            """
        ]
    )
    
    run_example(
        "EXEMPLO 3: Conflito Atômico Filters vs Constraints (Allow vs Block)",
        [
            """
            define intent Allow_Admin:
              from endpoint('Fin_PC1')
              to endpoint('Web_Server')
              allow traffic('80'), traffic('8080')
            """,
            """
            define intent Block_Sec:
              from endpoint('Fin_PC1')
              to endpoint('Web_Server')
              block traffic('8080')
            """
        ]
    )
    
    run_example(
        "EXEMPLO 4: Conflito Atômico em Cadeia de Serviços (SFCs)",
        [
            """
            define intent Rota_Desempenho:
              from endpoint('Fin_PC1')
              to endpoint('Web_Server')
              add middlebox('FW'), middlebox('LB')
            """,
            """
            define intent Rota_Seguranca:
              from endpoint('Fin_PC1')
              to endpoint('Web_Server')
              add middlebox('IDS'), middlebox('FW')
            """
        ]
    )
    
    run_example(
        "EXEMPLO 5: Conflito Atômico Total (Filters, Constraints e SFCs)",
        [
            """
            define intent Regra_Dev:
              from endpoint('Eng_PC1')
              to endpoint('App_Server')
              add middlebox('FW')
              allow traffic('80'), traffic('443'), traffic('8080')
            """,
            """
            define intent Regra_Sec:
              from endpoint('Eng_PC1')
              to endpoint('App_Server')
              add middlebox('DDoS'), middlebox('IDS')
              allow traffic('22')
              block traffic('8080')
            """
        ]
    )
    
    run_example(
        "EXEMPLO 6: Conflito Não-Atômico (Grupos) em Filters",
        [
            """
            define intent Geral_Eng:
              from group('Engenharia')
              to group('Datacenter')
              allow traffic('80')
            """,
            """
            define intent Especifico_Eng_DB:
              from endpoint('Eng_PC1')
              to endpoint('DB_Server')
              allow traffic('3306')
            """
        ]
    )
    
    run_example(
        "EXEMPLO 7: Conflito Não-Atômico (Grupos) em Filters e Constraints",
        [
            """
            define intent Matriz_Permite_Web:
              from group('Matriz')
              to group('Datacenter')
              allow traffic('80'), traffic('443')
            """,
            """
            define intent Financeiro_Bloqueia_DB:
              from group('Financeiro')
              to endpoint('DB_Server')
              block traffic('443')
            """
        ]
    )
    
    run_example(
        "EXEMPLO 8: Conflito Não-Atômico (Grupos) em Cadeia de Serviços (SFCs)",
        [
            """
            define intent Matriz_SFC_Basica:
              from group('Matriz')
              to group('Datacenter')
              add middlebox('FW')
            """,
            """
            define intent Financeiro_SFC_Avancada:
              from group('Financeiro')
              to group('Datacenter')
              add middlebox('IDS'), middlebox('WAF')
            """
        ]
    )
    
    run_example(
        "EXEMPLO 9: Conflito Não-Atômico Total (Filters, Constraints e SFCs sobre Grupos)",
        [
            """
            define intent Diretoria_Geral:
              from group('Matriz')
              to group('Cloud')
              add middlebox('FW'), middlebox('LB')
              allow traffic('80'), traffic('443'), traffic('8080')
            """,
            """
            define intent Seguranca_Financeiro:
              from group('Financeiro')
              to group('Cloud')
              add middlebox('DDoS'), middlebox('IDS')
              block traffic('8080')
            """,
            """
            define intent Excecao_PC1_App:
              from endpoint('Fin_PC1')
              to endpoint('App_Server')
              allow traffic('22')
            """
        ]
    )
