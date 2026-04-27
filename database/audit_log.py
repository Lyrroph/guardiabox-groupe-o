"""
Module de journalisation d'audit pour GuardiaBox.

Fournit une interface simplifiée pour enregistrer les opérations
de chiffrement/déchiffrement dans la base de données.
"""

from .db_manager import DatabaseManager
from typing import Optional


class AuditLogger:
    """Logger d'audit pour les opérations de chiffrement."""
    
    def __init__(self, db_path: str = None):
        """
        Initialise le logger d'audit.
        
        Args:
            db_path: Chemin vers la base de données (optionnel)
        """
        self.db_manager = DatabaseManager(db_path)
    
    def log_encryption(self, filename: str, file_size: int = None, 
                      success: bool = True):
        """
        Enregistre une opération de chiffrement.
        
        Args:
            filename: Nom du fichier chiffré
            file_size: Taille du fichier en octets
            success: Si l'opération a réussi
        """
        self.db_manager.log_operation('encrypt', filename, file_size, success)
    
    def log_decryption(self, filename: str, success: bool = True):
        """
        Enregistre une opération de déchiffrement.
        
        Args:
            filename: Nom du fichier déchiffré
            success: Si l'opération a réussi
        """
        self.db_manager.log_operation('decrypt', filename, None, success)
    
    def get_statistics(self) -> dict:
        """
        Récupère les statistiques d'utilisation.
        
        Returns:
            Dictionnaire avec les statistiques
        """
        return self.db_manager.get_statistics()
    
    def get_recent_activity(self, limit: int = 10) -> list:
        """
        Récupère l'activité récente.
        
        Args:
            limit: Nombre d'opérations à récupérer
            
        Returns:
            Liste des opérations récentes
        """
        return self.db_manager.get_recent_operations(limit)
    
    def clear_all_history(self):
        """Efface tout l'historique d'audit."""
        self.db_manager.clear_history()
    
    def close(self):
        """Ferme la connexion à la base de données."""
        self.db_manager.close()
    
    def __enter__(self):
        """Support pour le context manager."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Ferme la connexion à la sortie du context manager."""
        self.close()
