from typing import Dict, Optional, Set

class KillSwitchActiveError(Exception):
    """Raised when an operation is blocked by a global or repository kill switch."""
    pass

class KillSwitchManager:
    """
    Operator-level emergency kill switches:
    - Global mutation stop: immediately blocks all GitHub writes across all sessions.
    - Per-repository quarantine: freezes mutations for a specific repository.
    - Specific operation disable: e.g. freeze PR creation while allowing comments.
    """

    def __init__(self):
        self._global_mutation_kill: bool = False
        self._quarantined_repos: Set[str] = set()
        self._disabled_operations: Set[str] = set()

    def set_global_kill(self, active: bool = True) -> None:
        self._global_mutation_kill = active

    def is_global_kill_active(self) -> bool:
        return self._global_mutation_kill

    def quarantine_repository(self, repository: str) -> None:
        self._quarantined_repos.add(repository.lower().strip())

    def unquarantine_repository(self, repository: str) -> None:
        self._quarantined_repos.discard(repository.lower().strip())

    def is_repository_quarantined(self, repository: str) -> bool:
        return repository.lower().strip() in self._quarantined_repos

    def disable_operation(self, operation: str) -> None:
        self._disabled_operations.add(operation.lower().strip())

    def enable_operation(self, operation: str) -> None:
        self._disabled_operations.discard(operation.lower().strip())

    def is_operation_disabled(self, operation: str) -> bool:
        return operation.lower().strip() in self._disabled_operations

    def enforce(self, repository: str, operation: str) -> None:
        if self._global_mutation_kill:
            raise KillSwitchActiveError("Global mutation kill switch is ACTIVE. All external mutations are blocked.")

        if self.is_repository_quarantined(repository):
            raise KillSwitchActiveError(f"Repository '{repository}' is QUARANTINED. Mutations are blocked.")

        if self.is_operation_disabled(operation):
            raise KillSwitchActiveError(f"Operation '{operation}' is currently DISABLED by operator policy.")

# Singleton instance
_kill_switch_manager: Optional[KillSwitchManager] = None

def get_kill_switch_manager() -> KillSwitchManager:
    global _kill_switch_manager
    if _kill_switch_manager is None:
        _kill_switch_manager = KillSwitchManager()
    return _kill_switch_manager
