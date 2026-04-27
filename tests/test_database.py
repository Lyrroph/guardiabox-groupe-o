"""
Tests unitaires pour le module database.

Valide le fonctionnement du journal d'audit et du gestionnaire de base de données.
"""

import pytest
import os
import tempfile
from database.db_manager import DatabaseManager
from database.audit_log import AuditLogger


class TestDatabaseManager:
    """Tests pour le gestionnaire de base de données."""
    
    @pytest.fixture
    def temp_db(self):
        """Crée une base de données temporaire pour les tests."""
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        temp_file.close()
        db_path = temp_file.name
        
        yield db_path
        
        # Nettoyage
        if os.path.exists(db_path):
            os.remove(db_path)
    
    def test_init_database(self, temp_db):
        """Test l'initialisation de la base de données."""
        db = DatabaseManager(temp_db)
        assert db.conn is not None
        assert os.path.exists(temp_db)
        db.close()
    
    def test_log_encryption_operation(self, temp_db):
        """Test l'enregistrement d'une opération de chiffrement."""
        with DatabaseManager(temp_db) as db:
            db.log_operation('encrypt', 'test.txt', 1024, True)
            
            stats = db.get_statistics()
            assert stats['total_encryptions'] == 1
            assert stats['total_size_encrypted'] == 1024
    
    def test_log_decryption_operation(self, temp_db):
        """Test l'enregistrement d'une opération de déchiffrement."""
        with DatabaseManager(temp_db) as db:
            db.log_operation('decrypt', 'test.txt.crypt', None, True)
            
            stats = db.get_statistics()
            assert stats['total_decryptions'] == 1
    
    def test_hash_filename(self, temp_db):
        """Test le hachage des noms de fichiers."""
        with DatabaseManager(temp_db) as db:
            hash1 = db._hash_filename('secret.txt')
            hash2 = db._hash_filename('secret.txt')
            hash3 = db._hash_filename('other.txt')
            
            # Même fichier = même hash
            assert hash1 == hash2
            # Fichiers différents = hash différents
            assert hash1 != hash3
            # Hash en hexadécimal de 64 caractères (SHA-256)
            assert len(hash1) == 64
    
    def test_get_recent_operations(self, temp_db):
        """Test la récupération des opérations récentes."""
        with DatabaseManager(temp_db) as db:
            db.log_operation('encrypt', 'file1.txt', 100, True)
            db.log_operation('encrypt', 'file2.txt', 200, True)
            db.log_operation('decrypt', 'file1.txt.crypt', None, True)
            
            operations = db.get_recent_operations(limit=5)
            assert len(operations) == 3
            # Vérifie l'ordre (plus récent en premier)
            assert operations[0]['type'] == 'decrypt'
            assert operations[1]['type'] == 'encrypt'
    
    def test_clear_history(self, temp_db):
        """Test l'effacement de l'historique."""
        with DatabaseManager(temp_db) as db:
            db.log_operation('encrypt', 'file1.txt', 500, True)
            db.log_operation('decrypt', 'file2.txt', None, True)
            
            # Vérifier que les données existent
            stats_before = db.get_statistics()
            assert stats_before['total_encryptions'] == 1
            assert stats_before['total_decryptions'] == 1
            
            # Effacer l'historique
            db.clear_history()
            
            # Vérifier que tout est remis à zéro
            stats_after = db.get_statistics()
            assert stats_after['total_encryptions'] == 0
            assert stats_after['total_decryptions'] == 0
            assert stats_after['total_size_encrypted'] == 0
            
            operations = db.get_recent_operations()
            assert len(operations) == 0
    
    def test_failed_operation_not_counted(self, temp_db):
        """Test qu'une opération échouée n'est pas comptée dans les stats."""
        with DatabaseManager(temp_db) as db:
            db.log_operation('encrypt', 'file.txt', 100, success=False)
            
            stats = db.get_statistics()
            assert stats['total_encryptions'] == 0
            
            # Mais elle doit quand même être dans l'historique
            operations = db.get_recent_operations()
            assert len(operations) == 1
            assert operations[0]['success'] is False


class TestAuditLogger:
    """Tests pour le logger d'audit."""
    
    @pytest.fixture
    def temp_db(self):
        """Crée une base de données temporaire pour les tests."""
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        temp_file.close()
        db_path = temp_file.name
        
        yield db_path
        
        # Nettoyage
        if os.path.exists(db_path):
            os.remove(db_path)
    
    def test_log_encryption(self, temp_db):
        """Test l'enregistrement d'un chiffrement."""
        with AuditLogger(temp_db) as logger:
            logger.log_encryption('document.pdf', 2048, True)
            
            stats = logger.get_statistics()
            assert stats['total_encryptions'] == 1
            assert stats['total_size_encrypted'] == 2048
    
    def test_log_decryption(self, temp_db):
        """Test l'enregistrement d'un déchiffrement."""
        with AuditLogger(temp_db) as logger:
            logger.log_decryption('document.pdf.crypt', True)
            
            stats = logger.get_statistics()
            assert stats['total_decryptions'] == 1
    
    def test_get_recent_activity(self, temp_db):
        """Test la récupération de l'activité récente."""
        with AuditLogger(temp_db) as logger:
            logger.log_encryption('file1.txt', 100)
            logger.log_encryption('file2.txt', 200)
            logger.log_decryption('file1.txt.crypt')
            
            activity = logger.get_recent_activity(limit=3)
            assert len(activity) == 3
    
    def test_clear_all_history(self, temp_db):
        """Test l'effacement complet de l'historique."""
        with AuditLogger(temp_db) as logger:
            logger.log_encryption('file.txt', 500)
            logger.log_decryption('file.txt.crypt')
            
            # Vérifier que les données existent
            activity_before = logger.get_recent_activity()
            assert len(activity_before) == 2
            
            # Effacer
            logger.clear_all_history()
            
            # Vérifier que tout est vide
            activity_after = logger.get_recent_activity()
            assert len(activity_after) == 0
            
            stats = logger.get_statistics()
            assert stats['total_encryptions'] == 0
    
    def test_context_manager(self, temp_db):
        """Test l'utilisation comme context manager."""
        with AuditLogger(temp_db) as logger:
            logger.log_encryption('test.txt', 100)
        
        # La connexion doit être fermée
        assert logger.db_manager.conn is None


class TestDatabaseIntegration:
    """Tests d'intégration pour le module database."""
    
    @pytest.fixture
    def temp_db(self):
        """Crée une base de données temporaire pour les tests."""
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        temp_file.close()
        db_path = temp_file.name
        
        yield db_path
        
        # Nettoyage
        if os.path.exists(db_path):
            os.remove(db_path)
    
    def test_workflow_complet(self, temp_db):
        """Test un workflow complet d'utilisation."""
        with AuditLogger(temp_db) as logger:
            # Chiffrement de plusieurs fichiers
            logger.log_encryption('document1.pdf', 1024)
            logger.log_encryption('document2.docx', 2048)
            logger.log_encryption('image.png', 4096)
            
            # Déchiffrement
            logger.log_decryption('document1.pdf.crypt')
            logger.log_decryption('document2.docx.crypt')
            
            # Vérifier les statistiques
            stats = logger.get_statistics()
            assert stats['total_encryptions'] == 3
            assert stats['total_decryptions'] == 2
            assert stats['total_size_encrypted'] == 7168  # 1024 + 2048 + 4096
            
            # Vérifier l'historique
            activity = logger.get_recent_activity(limit=10)
            assert len(activity) == 5
    
    def test_no_password_stored(self, temp_db):
        """Test critique : vérifier qu'aucun mot de passe n'est jamais stocké."""
        with DatabaseManager(temp_db) as db:
            # Simuler plusieurs opérations
            db.log_operation('encrypt', 'secret_file.txt', 500, True)
            db.log_operation('decrypt', 'secret_file.txt.crypt', None, True)
            
            # Lire directement la BDD pour vérifier
            cursor = db.conn.cursor()
            cursor.execute("SELECT * FROM operations")
            rows = cursor.fetchall()
            
            # Vérifier qu'aucune colonne ne contient de mot de passe
            for row in rows:
                row_dict = dict(row)
                # Vérifier que les clés ne contiennent pas "password", "mdp", etc.
                assert 'password' not in str(row_dict).lower()
                assert 'mdp' not in str(row_dict).lower()
                assert 'secret' not in str(row_dict).lower()
                # Vérifier que le nom du fichier est haché (64 caractères hex)
                assert len(row_dict['file_hash']) == 64
