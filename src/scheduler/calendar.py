import logging
from typing import List
from src.domain.models import Intent
from src.core.engine import QICREngine
from src.repository.interfaces import IntentRepositoryInterface

logger = logging.getLogger(__name__)

class CalendarModule:
    def __init__(self, qicr_engine: QICREngine, repository: IntentRepositoryInterface):
        self.qicr = qicr_engine
        self.repo = repository
        self.intent_buffer: List[Intent] = []

    def declare_intent(self, intent: Intent) -> None:
        """Usuário declara a intenção. Ela vai para a sala de espera (buffer)."""
        self.intent_buffer.append(intent)
        logger.info(f"[Calendário] Intenção recebida e em espera: {intent}")

    def close_time_window(self) -> None:
        """Simula o fechamento da janela de tempo."""
        logger.info("="*50)
        logger.info("[Calendário] Janela de tempo fechada! Iniciando processamento...")
        
        if not self.intent_buffer:
            logger.info("Nenhuma intenção nova para processar.")
            return

        all_intents = self.repo.get_all() + self.intent_buffer
        logger.info(f"[*] Processando {len(self.intent_buffer)} nova(s) intenção(ões) + {len(self.repo.get_all())} ativa(s).")
        
        resolved_intents = self.qicr.resolve_conflicts(all_intents)
        self.repo.update_repository(resolved_intents)
        self.intent_buffer.clear()
        logger.info("="*50)
