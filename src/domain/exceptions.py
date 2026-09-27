class QICRError(Exception):
    """Base exception for QICR system."""
    pass

class KnowledgeGraphNodeError(QICRError):
    """Raised when a requested node is not found in the Knowledge Graph."""
    pass

class IntentConflictError(QICRError):
    """Raised when intents have unresolvable conflicts."""
    pass
