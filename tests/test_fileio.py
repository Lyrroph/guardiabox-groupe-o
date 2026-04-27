#!/usr/bin/env python3
"""
Tests unitaires pour le module fileio.

Ces tests valident les opérations de manipulation de fichiers sécurisée
et le chiffrement/déchiffrement de fichiers complets.
"""

import pytest
import sys
import os
import tempfile
import shutil
from pathlib import Path

# Ajout du répertoire parent au path pour les imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fileio import (
    valider_chemin,
    verifier_existence_fichier,
    lire_fichier_binaire,
    lire_fichier_texte,
    ecrire_fichier_binaire,
    ecrire_fichier_texte,
    generer_nom_fichier_chiffre,
    generer_nom_fichier_dechiffre,
    obtenir_taille_fichier,
    supprimer_fichier,
    chiffrer_fichier,
    dechiffrer_fichier,
    chiffrer_message,
    dechiffrer_message,
    PathTraversalError,
    FileOperationError,
    ChiffrementFichierError,
    DechiffrementFichierError,
    EXTENSION_CHIFFRE,
    EXTENSION_DECHIFFRE
)


class TestFileOperations:
    """Tests des operations de base sur les fichiers."""
    
    @pytest.fixture
    def temp_dir(self):
        """Cree un repertoire temporaire pour les tests."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        # Nettoyage apres le test
        shutil.rmtree(temp_dir, ignore_errors=True)
    
    def test_valider_chemin_normal(self, temp_dir):
        """Verifie la validation d'un chemin normal."""
        chemin = valider_chemin("fichier.txt", temp_dir)
        assert isinstance(chemin, Path)
        assert str(chemin).endswith("fichier.txt")
    
    def test_valider_chemin_path_traversal(self, temp_dir):
        """Verifie la detection d'injection de chemin."""
        with pytest.raises(PathTraversalError):
            valider_chemin("../../etc/passwd", temp_dir)
    
    def test_valider_chemin_vide(self, temp_dir):
        """Verifie qu'un chemin vide est rejete."""
        with pytest.raises(ValueError):
            valider_chemin("", temp_dir)
    
    def test_ecrire_et_lire_fichier_binaire(self, temp_dir):
        """Verifie l'ecriture et la lecture de fichiers binaires."""
        os.chdir(temp_dir)
        contenu = b"Donnees binaires test"
        
        ecrire_fichier_binaire("test.bin", contenu, ecraser=True)
        contenu_lu = lire_fichier_binaire("test.bin")
        
        assert contenu_lu == contenu
    
    def test_ecrire_et_lire_fichier_texte(self, temp_dir):
        """Verifie l'ecriture et la lecture de fichiers texte."""
        os.chdir(temp_dir)
        contenu = "Texte de test avec accents: éàèùç"
        
        ecrire_fichier_texte("test.txt", contenu, ecraser=True)
        contenu_lu = lire_fichier_texte("test.txt")
        
        assert contenu_lu == contenu
    
    def test_verifier_existence_fichier(self, temp_dir):
        """Verifie la detection d'existence de fichier."""
        os.chdir(temp_dir)
        
        # Fichier inexistant
        assert not verifier_existence_fichier("inexistant.txt")
        
        # Fichier existant
        ecrire_fichier_texte("existant.txt", "contenu", ecraser=True)
        assert verifier_existence_fichier("existant.txt")
    
    def test_lire_fichier_inexistant(self, temp_dir):
        """Verifie qu'une erreur est levee pour fichier inexistant."""
        os.chdir(temp_dir)
        with pytest.raises(FileNotFoundError):
            lire_fichier_binaire("inexistant.txt")
    
    def test_ecrire_fichier_existant_sans_ecraser(self, temp_dir):
        """Verifie qu'on ne peut pas ecraser sans option."""
        os.chdir(temp_dir)
        
        ecrire_fichier_texte("fichier.txt", "contenu1", ecraser=True)
        
        with pytest.raises(FileExistsError):
            ecrire_fichier_texte("fichier.txt", "contenu2", ecraser=False)
    
    def test_generer_nom_fichier_chiffre(self):
        """Verifie la generation du nom de fichier chiffre."""
        assert generer_nom_fichier_chiffre("doc.txt") == "doc.txt.crypt"
        assert generer_nom_fichier_chiffre("image.png") == "image.png.crypt"
    
    def test_generer_nom_fichier_dechiffre(self):
        """Verifie la generation du nom de fichier dechiffre."""
        assert generer_nom_fichier_dechiffre("doc.txt.crypt") == "doc.txt.decrypt"
        assert generer_nom_fichier_dechiffre("image.png.crypt") == "image.png.decrypt"
    
    def test_obtenir_taille_fichier(self, temp_dir):
        """Verifie l'obtention de la taille d'un fichier."""
        os.chdir(temp_dir)
        contenu = b"0123456789"
        
        ecrire_fichier_binaire("test.bin", contenu, ecraser=True)
        taille = obtenir_taille_fichier("test.bin")
        
        assert taille == len(contenu)
    
    def test_supprimer_fichier(self, temp_dir):
        """Verifie la suppression de fichier."""
        os.chdir(temp_dir)
        
        ecrire_fichier_texte("a_supprimer.txt", "contenu", ecraser=True)
        assert verifier_existence_fichier("a_supprimer.txt")
        
        supprimer_fichier("a_supprimer.txt")
        assert not verifier_existence_fichier("a_supprimer.txt")


class TestCryptoFile:
    """Tests du chiffrement/dechiffrement de fichiers."""
    
    @pytest.fixture
    def temp_dir(self):
        """Cree un repertoire temporaire pour les tests."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        # Nettoyage
        shutil.rmtree(temp_dir, ignore_errors=True)
    
    def test_chiffrer_fichier(self, temp_dir):
        """Verifie le chiffrement de fichier."""
        os.chdir(temp_dir)
        
        # Creation d'un fichier test
        contenu_original = "Contenu secret du fichier"
        ecrire_fichier_texte("document.txt", contenu_original, ecraser=True)
        
        # Chiffrement
        mot_de_passe = "MotDePasseTest123!"
        fichier_chiffre = chiffrer_fichier("document.txt", mot_de_passe)
        
        # Verifications
        assert fichier_chiffre == "document.txt.crypt"
        assert verifier_existence_fichier(fichier_chiffre)
        
        # Le fichier chiffre doit etre different de l'original
        contenu_chiffre = lire_fichier_binaire(fichier_chiffre)
        assert contenu_chiffre != contenu_original.encode('utf-8')
    
    def test_dechiffrer_fichier(self, temp_dir):
        """Verifie le dechiffrement de fichier."""
        os.chdir(temp_dir)
        
        # Creation et chiffrement
        contenu_original = "Message top secret !"
        ecrire_fichier_texte("secret.txt", contenu_original, ecraser=True)
        
        mot_de_passe = "Pass123!"
        chiffrer_fichier("secret.txt", mot_de_passe)
        
        # Dechiffrement
        fichier_dechiffre = dechiffrer_fichier("secret.txt.crypt", mot_de_passe)
        
        # Verifications
        assert fichier_dechiffre == "secret.txt.decrypt"
        assert verifier_existence_fichier(fichier_dechiffre)
        
        contenu_recupere = lire_fichier_texte(fichier_dechiffre)
        assert contenu_recupere == contenu_original
    
    def test_chiffrer_dechiffrer_cycle_complet(self, temp_dir):
        """TEST CRUCIAL: Chiffrement puis dechiffrement = donnee initiale."""
        os.chdir(temp_dir)
        
        # Plusieurs contenus de test
        contenus_test = [
            "Message simple",
            "Message avec accents: éàèùç!",
            "Message\navec\nplusieurs\nlignes",
            "Message avec caracteres speciaux: !@#$%^&*()",
            "A" * 10000,  # Message long
        ]
        
        mot_de_passe = "TestPassword123!"
        
        for i, contenu_original in enumerate(contenus_test):
            nom_fichier = f"test_{i}.txt"
            
            # Creation du fichier
            ecrire_fichier_texte(nom_fichier, contenu_original, ecraser=True)
            
            # Chiffrement
            chiffrer_fichier(nom_fichier, mot_de_passe)
            
            # Dechiffrement
            dechiffrer_fichier(f"{nom_fichier}.crypt", mot_de_passe)
            
            # Verification
            contenu_recupere = lire_fichier_texte(f"{nom_fichier}.decrypt")
            assert contenu_recupere == contenu_original
    
    def test_dechiffrement_mauvais_mot_de_passe(self, temp_dir):
        """TEST CRUCIAL: Mauvais mot de passe doit echouer."""
        os.chdir(temp_dir)
        
        # Creation et chiffrement
        ecrire_fichier_texte("data.txt", "Donnees sensibles", ecraser=True)
        chiffrer_fichier("data.txt", "BonMotDePasse!")
        
        # Tentative de dechiffrement avec mauvais mot de passe
        with pytest.raises(DechiffrementFichierError):
            dechiffrer_fichier("data.txt.crypt", "MauvaisMotDePasse!")
    
    def test_chiffrer_fichier_inexistant(self, temp_dir):
        """Verifie qu'on ne peut pas chiffrer un fichier inexistant."""
        os.chdir(temp_dir)
        
        with pytest.raises(FileNotFoundError):
            chiffrer_fichier("inexistant.txt", "Password123!")
    
    def test_dechiffrer_fichier_inexistant(self, temp_dir):
        """Verifie qu'on ne peut pas dechiffrer un fichier inexistant."""
        os.chdir(temp_dir)
        
        with pytest.raises(FileNotFoundError):
            dechiffrer_fichier("inexistant.crypt", "Password123!")
    
    def test_dechiffrer_fichier_corrompu(self, temp_dir):
        """Verifie qu'un fichier corrompu est detecte."""
        os.chdir(temp_dir)
        
        # Creation d'un faux fichier .crypt (trop petit)
        ecrire_fichier_binaire("corrompu.crypt", b"donnees_invalides", ecraser=True)
        
        with pytest.raises(DechiffrementFichierError):
            dechiffrer_fichier("corrompu.crypt", "Password123!")
    
    def test_chiffrer_message(self, temp_dir):
        """Verifie le chiffrement de message direct."""
        os.chdir(temp_dir)
        
        message = "Mon message secret"
        mot_de_passe = "Pass123!"
        
        fichier_chiffre = chiffrer_message(message, mot_de_passe, "msg.txt")
        
        assert fichier_chiffre == "msg.txt.crypt"
        assert verifier_existence_fichier(fichier_chiffre)
    
    def test_dechiffrer_message(self, temp_dir):
        """Verifie le dechiffrement de message direct."""
        os.chdir(temp_dir)
        
        message_original = "Message ultra-secret !"
        mot_de_passe = "Password123!"
        
        # Chiffrement
        fichier_chiffre = chiffrer_message(message_original, mot_de_passe, "secret.txt")
        
        # Dechiffrement
        message_recupere = dechiffrer_message(fichier_chiffre, mot_de_passe)
        
        assert message_recupere == message_original
    
    def test_chiffrer_fichier_binaire(self, temp_dir):
        """Verifie le chiffrement de fichiers binaires."""
        os.chdir(temp_dir)
        
        # Creation d'un fichier binaire
        donnees_binaires = bytes(range(256))
        ecrire_fichier_binaire("data.bin", donnees_binaires, ecraser=True)
        
        # Chiffrement
        mot_de_passe = "BinaryPass123!"
        chiffrer_fichier("data.bin", mot_de_passe)
        
        # Dechiffrement
        dechiffrer_fichier("data.bin.crypt", mot_de_passe)
        
        # Verification
        donnees_recuperees = lire_fichier_binaire("data.bin.decrypt")
        assert donnees_recuperees == donnees_binaires


class TestPathTraversal:
    """Tests de securite contre les attaques par injection de chemin."""
    
    @pytest.fixture
    def temp_dir(self):
        """Cree un repertoire temporaire pour les tests."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir, ignore_errors=True)
    
    def test_path_traversal_simple(self, temp_dir):
        """Verifie le blocage de ../ simple."""
        with pytest.raises(PathTraversalError):
            valider_chemin("../fichier.txt", temp_dir)
    
    def test_path_traversal_multiple(self, temp_dir):
        """Verifie le blocage de ../../ multiple."""
        with pytest.raises(PathTraversalError):
            valider_chemin("../../etc/passwd", temp_dir)
    
    def test_path_traversal_absolu(self, temp_dir):
        """Verifie le blocage de chemins absolus hors repertoire."""
        with pytest.raises(PathTraversalError):
            valider_chemin("/etc/passwd", temp_dir)
    
    def test_chemin_relatif_valide(self, temp_dir):
        """Verifie qu'un chemin relatif valide fonctionne."""
        chemin = valider_chemin("sous_dossier/fichier.txt", temp_dir)
        assert isinstance(chemin, Path)
    
    def test_chemin_avec_point(self, temp_dir):
        """Verifie que ./ est accepte."""
        chemin = valider_chemin("./fichier.txt", temp_dir)
        assert isinstance(chemin, Path)


class TestIntegrationFileio:
    """Tests d'integration complets du module fileio."""
    
    @pytest.fixture
    def temp_dir(self):
        """Cree un repertoire temporaire pour les tests."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir, ignore_errors=True)
    
    def test_workflow_complet(self, temp_dir):
        """Simule un workflow utilisateur complet."""
        os.chdir(temp_dir)
        
        # 1. Utilisateur cree un fichier
        contenu_original = "Donnees confidentielles de l'entreprise"
        ecrire_fichier_texte("confidentiel.txt", contenu_original, ecraser=True)
        
        # 2. Utilisateur chiffre le fichier
        mot_de_passe = "MotDePasseEntreprise2026!"
        fichier_chiffre = chiffrer_fichier("confidentiel.txt", mot_de_passe)
        
        # 3. Fichier chiffre existe
        assert verifier_existence_fichier(fichier_chiffre)
        taille_chiffre = obtenir_taille_fichier(fichier_chiffre)
        assert taille_chiffre > 0
        
        # 4. Suppression du fichier original (optionnel)
        supprimer_fichier("confidentiel.txt")
        assert not verifier_existence_fichier("confidentiel.txt")
        
        # 5. Plus tard, utilisateur dechiffre
        fichier_dechiffre = dechiffrer_fichier(fichier_chiffre, mot_de_passe)
        
        # 6. Verification du contenu
        contenu_recupere = lire_fichier_texte(fichier_dechiffre)
        assert contenu_recupere == contenu_original
    
    def test_format_fichier_crypt(self, temp_dir):
        """Verifie le format exact du fichier .crypt (salt+nonce+ciphertext+tag)."""
        os.chdir(temp_dir)
        
        from security import SALT_SIZE, NONCE_SIZE, TAG_SIZE
        
        # Chiffrement d'un message court
        message = "Test"
        ecrire_fichier_texte("test.txt", message, ecraser=True)
        chiffrer_fichier("test.txt", "Password123!")
        
        # Lecture du fichier chiffre
        fichier_crypt = lire_fichier_binaire("test.txt.crypt")
        
        # Verification de la structure
        assert len(fichier_crypt) >= SALT_SIZE + NONCE_SIZE + TAG_SIZE
        
        # Extraction des composants
        sel = fichier_crypt[:SALT_SIZE]
        nonce = fichier_crypt[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
        tag = fichier_crypt[-TAG_SIZE:]
        
        assert len(sel) == SALT_SIZE
        assert len(nonce) == NONCE_SIZE
        assert len(tag) == TAG_SIZE
