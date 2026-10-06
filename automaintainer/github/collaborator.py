"""
Maintainer & Collaborator Authorization Verifier.
Re-exports the unified GitHubCollaboratorResolver for backwards compatibility.
"""
from automaintainer.github.collaborator_resolver import GitHubCollaboratorResolver

__all__ = ["GitHubCollaboratorResolver"]
