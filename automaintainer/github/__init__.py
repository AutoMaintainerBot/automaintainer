"""
AutoMaintainer GitHub Integration Package.
Provides multi-tenant authentication, webhook handling, PR synchronization,
collaborator validation, and workflow installer capabilities.
"""
from automaintainer.github.auth import InstallationTokenBroker, InstallationTokenRecord
from automaintainer.github.collaborator_resolver import GitHubCollaboratorResolver

__all__ = [
    "InstallationTokenBroker",
    "InstallationTokenRecord",
    "GitHubCollaboratorResolver",
]
