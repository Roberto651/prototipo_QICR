import logging
from typing import List
from src.domain.models import Intent
from src.repository.interfaces import IntentRepositoryInterface

logger = logging.getLogger(__name__)

class InMemoryIntentRepository(IntentRepositoryInterface):
    def __init__(self):
        self._active_intents: List[Intent] = []

    def update_repository(self, resolved_intents: List[Intent]) -> None:
        self._active_intents = resolved_intents
        logger.info(f"[*] Repositório atualizado síncronamente. Total de intenções ativas: {len(self._active_intents)}")

    def get_all(self) -> List[Intent]:
        return self._active_intents
