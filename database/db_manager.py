"""
Gestionnaire de base de données SQLite pour GuardiaBox.

Ce module gère la connexion, la création et les opérations sur la base de données.
Toutes les données sensibles sont hachées avant stockage.
"""

import sqlite3
import os
from pathlib import Path
from datetime import datetime
import hashlib


class DatabaseManager:
    """Gestionnaire de la base de données SQLite."""
    
    def __init__(self, db_path: str = None):
        """
        Initialise le gestionnaire de base de données.
        
        Args:
            db_path: Chemin vers le fichier de base de données.
                     Par défaut : guardiabox_audit.db dans le dossier courant
        """
        if db_path is None:
            db_path = os.path.join(os.getcwd(), "guardiabox_audit.db")
        
        self.db_path = db_path
        self.conn = None
        self._init_database()
    
    def _init_database(self):
        """Initialise la base de données et crée les tables si nécessaire."""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row  # Pour accéder aux colonnes par nom
        
        cursor = self.conn.cursor()
        
        # Table pour les opérations de chiffrement/déchiffrement
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS operations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation_type TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                file_size INTEGER,
                timestamp TEXT NOT NULL,
                success BOOLEAN NOT NULL
            )
        """)
        
        # Table pour les statistiques globales
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                total_encryptions INTEGER DEFAULT 0,
                total_decryptions INTEGER DEFAULT 0,
                total_size_encrypted INTEGER DEFAULT 0,
                last_updated TEXT NOT NULL
            )
        """)
        
        # Initialiser les statistiques si la table est vide
        cursor.execute("SELECT COUNT(*) as count FROM statistics")
        if cursor.fetchone()['count'] == 0:
            cursor.execute("""
                INSERT INTO statistics (total_encryptions, total_decryptions, 
                                       total_size_encrypted, last_updated)
                VALUES (0, 0, 0, ?)
            """, (datetime.now().isoformat(),))
        
        self.conn.commit()
    
    def _hash_filename(self, filename: str) -> str:
        """
        Hache un nom de fichier avec SHA-256.
        
        Args:
            filename: Nom du fichier à hacher
            
        Returns:
            Hash SHA-256 du nom de fichier
        """
        return hashlib.sha256(filename.encode('utf-8')).hexdigest()
    
    def log_operation(self, operation_type: str, filename: str, 
                     file_size: int = None, success: bool = True):
        """
        Enregistre une opération dans le journal d'audit.
        
        Args:
            operation_type: Type d'opération ('encrypt' ou 'decrypt')
            filename: Nom du fichier (sera haché)
            file_size: Taille du fichier en octets
            success: Si l'opération a réussi
        """
        if self.conn is None:
            return
        
        file_hash = self._hash_filename(filename)
        timestamp = datetime.now().isoformat()
        
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO operations (operation_type, file_hash, file_size, 
                                   timestamp, success)
            VALUES (?, ?, ?, ?, ?)
        """, (operation_type, file_hash, file_size, timestamp, success))
        
        # Mettre à jour les statistiques
        if success:
            if operation_type == 'encrypt':
                cursor.execute("""
                    UPDATE statistics 
                    SET total_encryptions = total_encryptions + 1,
                        total_size_encrypted = total_size_encrypted + ?,
                        last_updated = ?
                    WHERE id = 1
                """, (file_size or 0, timestamp))
            elif operation_type == 'decrypt':
                cursor.execute("""
                    UPDATE statistics 
                    SET total_decryptions = total_decryptions + 1,
                        last_updated = ?
                    WHERE id = 1
                """, (timestamp,))
        
        self.conn.commit()
    
    def get_statistics(self) -> dict:
        """
        Récupère les statistiques globales.
        
        Returns:
            Dictionnaire contenant les statistiques
        """
        if self.conn is None:
            return {}
        
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM statistics WHERE id = 1")
        row = cursor.fetchone()
        
        if row:
            return {
                'total_encryptions': row['total_encryptions'],
                'total_decryptions': row['total_decryptions'],
                'total_size_encrypted': row['total_size_encrypted'],
                'last_updated': row['last_updated']
            }
        return {}
    
    def get_recent_operations(self, limit: int = 10) -> list:
        """
        Récupère les opérations récentes.
        
        Args:
            limit: Nombre maximum d'opérations à récupérer
            
        Returns:
            Liste des opérations récentes
        """
        if self.conn is None:
            return []
        
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT operation_type, file_hash, file_size, timestamp, success
            FROM operations
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))
        
        operations = []
        for row in cursor.fetchall():
            operations.append({
                'type': row['operation_type'],
                'file_hash': row['file_hash'][:16] + '...',  # Afficher seulement les premiers caractères
                'size': row['file_size'],
                'timestamp': row['timestamp'],
                'success': bool(row['success'])
            })
        
        return operations
    
    def clear_history(self):
        """Efface tout l'historique des opérations."""
        if self.conn is None:
            return
        
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM operations")
        cursor.execute("""
            UPDATE statistics 
            SET total_encryptions = 0,
                total_decryptions = 0,
                total_size_encrypted = 0,
                last_updated = ?
            WHERE id = 1
        """, (datetime.now().isoformat(),))
        self.conn.commit()
    
    def close(self):
        """Ferme la connexion à la base de données."""
        if self.conn:
            self.conn.close()
            self.conn = None
    
    def __enter__(self):
        """Support pour le context manager."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Ferme la connexion à la sortie du context manager."""
        self.close()
