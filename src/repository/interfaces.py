from abc import ABC, abstractmethod
from typing import List
from src.domain.models import Intent

class IntentRepositoryInterface(ABC):
    @abstractmethod
    def update_repository(self, resolved_intents: List[Intent]) -> None:
        pass

    @abstractmethod
    def get_all(self) -> List[Intent]:
        pass
