"""
Module de gestion de base de données pour GuardiaBox.

Fournit un système de journal d'audit sécurisé pour tracer les opérations
de chiffrement/déchiffrement sans jamais stocker les mots de passe.
"""

from .db_manager import DatabaseManager
from .audit_log import AuditLogger

__all__ = ['DatabaseManager', 'AuditLogger']
