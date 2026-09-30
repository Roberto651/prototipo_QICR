import logging
from src.core.kg import KnowledgeGraph
from src.core.engine import QICREngine
from src.repository.memory import InMemoryIntentRepository
from src.scheduler.calendar import CalendarModule
from src.domain.models import Intent
from src.domain.parser import NileParser

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def main():
    setup_logging()
    logger = logging.getLogger("MAIN")
    
    # 1. Configurando o Grafo de Conhecimento
    logger.info("Configurando o Grafo de Conhecimento (Topologia)...")
    kg = KnowledgeGraph()
    kg.add_inclusion("Campus", ["Academy", "Service"])
    kg.add_inclusion("Service", ["DNS", "Web", "DB"])
    kg.add_inclusion("Academy", ["A1", "A2", "B1", "B2", "D"])
    kg.add_inclusion("Build1", ["ZoneA", "ZoneB"])
    kg.add_inclusion("Build2", ["ZoneC", "ZoneD"])
    kg.add_inclusion("ZoneA", ["A1", "A2"])
    kg.add_inclusion("ZoneB", ["B1", "B2"])
    kg.add_inclusion("ZoneC", ["DNS", "Web", "DB"])
    kg.add_inclusion("ZoneD", ["D"])

    # 2. Inicializando os Sistemas
    repo = InMemoryIntentRepository()
    engine = QICREngine(kg)
    calendar = CalendarModule(engine, repo)

    # ---------------------------------------------------------
    # SIMULAÇÃO: JANELA DE TEMPO 1 (Regras Isoladas)
    # ---------------------------------------------------------
    logger.info("--- INICIANDO JANELA 1 ---")
    calendar.declare_intent(NileParser.parse("""
    define intent Academy_Web:
      from group('Academy')
      to endpoint('Web')
      add middlebox('FW'), middlebox('LB')
      allow traffic('80')
    """))
    calendar.declare_intent(NileParser.parse("""
    define intent Web_DB:
      from endpoint('Web')
      to endpoint('DB')
      add middlebox('FW')
      allow traffic('3306')
    """))
    
    calendar.close_time_window()

    logger.info("Estado Atual da Rede (Repositório após Janela 1):")
    for i in repo.get_all():
        logger.info(f"  {i}")
    
    # ---------------------------------------------------------
    # SIMULAÇÃO: JANELA DE TEMPO 2 (Emergência/Novas Regras)
    # ---------------------------------------------------------
    logger.info("\n--- INICIANDO JANELA 2 ---")
    calendar.declare_intent(NileParser.parse("""
    define intent A1_B1:
      from endpoint('A1')
      to endpoint('B1')
      add middlebox('FW'), middlebox('DDoS')
      allow traffic('22'), traffic('23'), traffic('53')
    """))
    calendar.declare_intent(NileParser.parse("""
    define intent Academy_DNS:
      from group('Academy')
      to endpoint('DNS')
      add middlebox('FW'), middlebox('IDS')
      allow traffic('53')
    """))
    
    # Nova regra restritiva que causará conflito:
    calendar.declare_intent(NileParser.parse("""
    define intent ZoneA_ZoneB:
      from group('ZoneA')
      to group('ZoneB')
      block traffic('2000')
    """))

    calendar.close_time_window()

    logger.info("Estado Atual da Rede (Repositório após Janela 2):")
    for i in repo.get_all():
        logger.info(f"  {i}")

    # ---------------------------------------------------------
    # SIMULAÇÃO: JANELA DE TEMPO 3 (Conflito Direto)
    # ---------------------------------------------------------
    logger.info("\n--- INICIANDO JANELA 3 (Conflito Direto) ---")
    
    # Intenção 1 (Desenvolvedor): Quer liberar as portas 443 e 8080 para tráfego do A1 para a Web
    calendar.declare_intent(NileParser.parse("""
    define intent Dev_A1_Web:
      from endpoint('A1')
      to endpoint('Web')
      add middlebox('FW')
      allow traffic('443'), traffic('8080')
    """))
    
    # Intenção 2 (Segurança): Quer bloquear explicitamente a porta 8080 do A1 para a Web
    calendar.declare_intent(NileParser.parse("""
    define intent Sec_A1_Web:
      from endpoint('A1')
      to endpoint('Web')
      add middlebox('IDS')
      block traffic('8080')
    """))

    calendar.close_time_window()

    logger.info("Estado Atual da Rede (Repositório após Janela 3):")
    for i in repo.get_all():
        logger.info(f"  {i}")

    # ---------------------------------------------------------
    # SIMULAÇÃO: JANELA DE TEMPO 4 (Ordenação Topológica de SFC)
    # ---------------------------------------------------------
    logger.info("\n--- INICIANDO JANELA 4 (Ordenação Topológica de SFC) ---")
    
    # Criando um cenário focado apenas na resolução SFC
    calendar.declare_intent(NileParser.parse("""
    define intent A1_Web_4:
      from endpoint('A1')
      to endpoint('Web')
      add middlebox('FW'), middlebox('LB')
      allow traffic('80')
    """))
    calendar.declare_intent(NileParser.parse("""
    define intent ZoneA_Web_4:
      from group('ZoneA')
      to endpoint('Web')
      add middlebox('DDoS'), middlebox('FW'), middlebox('IDS')
      allow traffic('80')
    """))
    calendar.declare_intent(NileParser.parse("""
    define intent A1_ZoneC_4:
      from endpoint('A1')
      to group('ZoneC')
      add middlebox('FW'), middlebox('WAF')
      allow traffic('80')
    """))

    calendar.close_time_window()

    logger.info("Estado Atual da Rede (Repositório após Janela 4):")
    for i in repo.get_all():
        logger.info(f"  {i}")

    # ---------------------------------------------------------
    # SIMULAÇÃO: JANELA DE TEMPO 5 (Conflitos de QoS - III.B e III.C)
    # ---------------------------------------------------------
    logger.info("\n--- INICIANDO JANELA 5 (Conflitos QoS e Resolução) ---")
    
    # Intenção 1 (Intra-Intent Conflict: Bandwidth excessiva)
    calendar.declare_intent(NileParser.parse("""
    define intent QoS_Overcommit:
      from endpoint('A1')
      to endpoint('Web')
      demand bandwidth('150.0')
    """))

    # Intenção 2 (Alta Prioridade)
    calendar.declare_intent(NileParser.parse("""
    define intent QoS_HighPrio:
      from endpoint('A2')
      to endpoint('DB')
      demand bandwidth('30.0')
      demand latency('2.0')
      demand packet_loss('0.5')
      set priority('90')
    """))

    # Intenção 3 (Prioridade Normal - Concorrendo por banda)
    calendar.declare_intent(NileParser.parse("""
    define intent QoS_Normal_1:
      from endpoint('B1')
      to endpoint('Web')
      demand bandwidth('60.0')
      set priority('40')
    """))

    # Intenção 4 (Prioridade Normal - Concorrendo por banda)
    calendar.declare_intent(NileParser.parse("""
    define intent QoS_Normal_2:
      from endpoint('B2')
      to endpoint('DB')
      demand bandwidth('60.0')
      set priority('20')
    """))

    calendar.close_time_window()

    logger.info("Estado Atual da Rede (Repositório após Janela 5):")
    for i in repo.get_all():
        logger.info(f"  {i}")

    # ---------------------------------------------------------
    # SIMULAÇÃO: JANELA DE TEMPO 6 (Teste de Anti-Envenenamento)
    # ---------------------------------------------------------
    logger.info("\n--- INICIANDO JANELA 6 (Teste do Anti-Envenenamento de Junção) ---")
    
    # Intenção 1: Válida e razoável
    calendar.declare_intent(NileParser.parse("""
    define intent QoS_Valid_A1_DB:
      from endpoint('A1')
      to endpoint('DB')
      demand bandwidth('70.0')
      set priority('50')
    """))

    # Intenção 2: Absurda e com a mesma origem e destino da anterior.
    # Se a mesclagem estrutural ocorresse ANTES do filtro individual, 
    # ela "envenenaria" a intenção 1 ao tirar o max(),
    # e ambas seriam descartadas pelo limite sistêmico.
    calendar.declare_intent(NileParser.parse("""
    define intent QoS_Poison_A1_DB:
      from endpoint('A1')
      to endpoint('DB')
      demand bandwidth('1500.0')
    """))

    calendar.close_time_window()

    logger.info("Estado Atual da Rede (Repositório após Janela 6):")
    for i in repo.get_all():
        if i.src == 'A1' and i.dst == 'DB':
            logger.info(f"  {i}")

if __name__ == "__main__":
    main()
