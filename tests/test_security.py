#!/usr/bin/env python3
"""
Tests unitaires pour le module security.

Ces tests valident le bon fonctionnement des opérations cryptographiques
et de validation des mots de passe.
"""

import pytest
import sys
import os

# Ajout du répertoire parent au path pour les imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from security import (
    generer_sel,
    deriver_cle,
    deriver_cle_complete,
    chiffrer_donnees,
    dechiffrer_donnees,
    chiffrer_texte,
    dechiffrer_texte,
    valider_mot_de_passe,
    calculer_entropie,
    evaluer_force_mot_de_passe,
    SALT_SIZE,
    KEY_SIZE,
    NONCE_SIZE,
    TAG_SIZE
)

from cryptography.exceptions import InvalidTag


class TestKeyDerivation:
    """Tests du module de derivation de cle."""
    
    def test_generer_sel(self):
        """Verifie que le sel genere a la bonne taille."""
        sel = generer_sel()
        assert isinstance(sel, bytes)
        assert len(sel) == SALT_SIZE
    
    def test_generer_sel_aleatoire(self):
        """Verifie que chaque sel genere est unique."""
        sel1 = generer_sel()
        sel2 = generer_sel()
        assert sel1 != sel2
    
    def test_deriver_cle(self):
        """Verifie la derivation de cle avec PBKDF2."""
        sel = generer_sel()
        cle = deriver_cle("MonMotDePasse123!", sel)
        
        assert isinstance(cle, bytes)
        assert len(cle) == KEY_SIZE
    
    def test_deriver_cle_deterministe(self):
        """Verifie que la derivation est deterministe (meme resultat avec meme entree)."""
        sel = generer_sel()
        mot_de_passe = "TestPassword!"
        
        cle1 = deriver_cle(mot_de_passe, sel)
        cle2 = deriver_cle(mot_de_passe, sel)
        
        assert cle1 == cle2
    
    def test_deriver_cle_differente_avec_sel_different(self):
        """Verifie que des sels differents produisent des cles differentes."""
        mot_de_passe = "TestPassword!"
        sel1 = generer_sel()
        sel2 = generer_sel()
        
        cle1 = deriver_cle(mot_de_passe, sel1)
        cle2 = deriver_cle(mot_de_passe, sel2)
        
        assert cle1 != cle2
    
    def test_deriver_cle_complete(self):
        """Verifie la fonction de derivation complete."""
        sel, cle = deriver_cle_complete("Password123!")
        
        assert isinstance(sel, bytes)
        assert isinstance(cle, bytes)
        assert len(sel) == SALT_SIZE
        assert len(cle) == KEY_SIZE
    
    def test_deriver_cle_avec_sel_invalide(self):
        """Verifie que les validations fonctionnent."""
        with pytest.raises(ValueError):
            deriver_cle("password", b"trop_court")


class TestCrypto:
    """Tests du module de chiffrement/dechiffrement."""
    
    def test_chiffrer_donnees(self):
        """Verifie le chiffrement de donnees."""
        _, cle = deriver_cle_complete("TestPassword!")
        donnees = b"Message secret"
        
        nonce, chiffre, tag = chiffrer_donnees(donnees, cle)
        
        assert isinstance(nonce, bytes)
        assert isinstance(chiffre, bytes)
        assert isinstance(tag, bytes)
        assert len(nonce) == NONCE_SIZE
        assert len(tag) == TAG_SIZE
        assert chiffre != donnees  # Les donnees sont bien chiffrees
    
    def test_dechiffrer_donnees(self):
        """Verifie le dechiffrement de donnees."""
        _, cle = deriver_cle_complete("TestPassword!")
        donnees_originales = b"Message secret"
        
        nonce, chiffre, tag = chiffrer_donnees(donnees_originales, cle)
        donnees_dechiffrees = dechiffrer_donnees(chiffre, cle, nonce, tag)
        
        assert donnees_dechiffrees == donnees_originales
    
    def test_chiffrer_dechiffrer_cycle_complet(self):
        """TEST CRUCIAL: Verifie que Dechiffrement(Chiffrement(Donnee)) == Donnee initiale."""
        mot_de_passe = "MonSuperMotDePasse123!"
        _, cle = deriver_cle_complete(mot_de_passe)
        
        # Test avec plusieurs types de donnees
        tests_donnees = [
            b"Message simple",
            b"Message avec des caracteres speciaux: !@#$%^&*()",
            b"Message\navec\ndes\nligne\nde\nretour",
            b"Message tres long " * 1000,
            b"",  # Message vide
            bytes(range(256)),  # Tous les octets possibles
        ]
        
        for donnees_originales in tests_donnees:
            nonce, chiffre, tag = chiffrer_donnees(donnees_originales, cle)
            donnees_recuperees = dechiffrer_donnees(chiffre, cle, nonce, tag)
            assert donnees_recuperees == donnees_originales
    
    def test_dechiffrement_avec_mauvais_mot_de_passe(self):
        """TEST CRUCIAL: Verifie qu'un mot de passe incorrect empeche le dechiffrement."""
        # Chiffrement avec un mot de passe
        _, cle_correcte = deriver_cle_complete("BonMotDePasse!")
        donnees = b"Message secret"
        nonce, chiffre, tag = chiffrer_donnees(donnees, cle_correcte)
        
        # Tentative de dechiffrement avec un mauvais mot de passe
        _, cle_incorrecte = deriver_cle_complete("MauvaisMotDePasse!")
        
        with pytest.raises(InvalidTag):
            dechiffrer_donnees(chiffre, cle_incorrecte, nonce, tag)
    
    def test_dechiffrement_avec_tag_corrompu(self):
        """Verifie que des donnees corrompues sont detectees."""
        _, cle = deriver_cle_complete("TestPassword!")
        donnees = b"Message secret"
        nonce, chiffre, tag = chiffrer_donnees(donnees, cle)
        
        # Corruption du tag
        tag_corrompu = bytes([b ^ 0xFF for b in tag])
        
        with pytest.raises(InvalidTag):
            dechiffrer_donnees(chiffre, cle, nonce, tag_corrompu)
    
    def test_chiffrer_texte(self):
        """Verifie le chiffrement de texte (string)."""
        _, cle = deriver_cle_complete("TestPassword!")
        texte = "Message en francais avec accents: éàèùç!"
        
        nonce, chiffre, tag = chiffrer_texte(texte, cle)
        
        assert isinstance(nonce, bytes)
        assert isinstance(chiffre, bytes)
        assert isinstance(tag, bytes)
    
    def test_dechiffrer_texte(self):
        """Verifie le dechiffrement de texte (string)."""
        _, cle = deriver_cle_complete("TestPassword!")
        texte_original = "Message en francais avec accents: éàèùç!"
        
        nonce, chiffre, tag = chiffrer_texte(texte_original, cle)
        texte_recupere = dechiffrer_texte(chiffre, cle, nonce, tag)
        
        assert texte_recupere == texte_original
    
    def test_chiffrement_avec_nonce_unique(self):
        """Verifie que chaque chiffrement utilise un nonce unique."""
        _, cle = deriver_cle_complete("TestPassword!")
        donnees = b"Message"
        
        nonce1, _, _ = chiffrer_donnees(donnees, cle)
        nonce2, _, _ = chiffrer_donnees(donnees, cle)
        
        assert nonce1 != nonce2


class TestPasswordValidator:
    """Tests du module de validation de mot de passe."""
    
    def test_calculer_entropie(self):
        """Verifie le calcul d'entropie."""
        # Mot de passe faible
        entropie_faible = calculer_entropie("abc")
        assert entropie_faible < 20
        
        # Mot de passe fort
        entropie_forte = calculer_entropie("Abc123!@#XYZ")
        assert entropie_forte > 50
    
    def test_valider_mot_de_passe_trop_court(self):
        """Verifie la validation d'un mot de passe trop court."""
        est_valide, erreurs = valider_mot_de_passe("abc")
        assert not est_valide
        assert len(erreurs) > 0
    
    def test_valider_mot_de_passe_valide(self):
        """Verifie la validation d'un mot de passe valide."""
        est_valide, erreurs = valider_mot_de_passe("MonMotDePasse123!")
        assert est_valide
        assert len(erreurs) == 0
    
    def test_valider_mot_de_passe_mode_strict(self):
        """Verifie la validation en mode strict."""
        # Mot de passe sans caracteres speciaux
        est_valide, erreurs = valider_mot_de_passe("Password123", strict=True)
        assert not est_valide
        
        # Mot de passe complet
        est_valide, erreurs = valider_mot_de_passe("Password123!", strict=True)
        assert est_valide
    
    def test_evaluer_force_mot_de_passe(self):
        """Verifie l'evaluation de la force du mot de passe."""
        assert evaluer_force_mot_de_passe("abc") in ["Tres faible", "Faible"]
        assert evaluer_force_mot_de_passe("password") in ["Faible", "Moyen"]
        assert evaluer_force_mot_de_passe("Password123!") in ["Moyen", "Fort", "Tres fort"]
        assert evaluer_force_mot_de_passe("UnTresLongMotDePasse123!@#") in ["Fort", "Tres fort"]


class TestIntegrationComplete:
    """Tests d'integration complets du systeme de chiffrement."""
    
    def test_scenario_complet_chiffrement_dechiffrement(self):
        """Scenario complet: mot de passe -> cle -> chiffrement -> dechiffrement."""
        # 1. L'utilisateur fournit un mot de passe
        mot_de_passe = "MonMotDePasseSecurise2026!"
        
        # 2. Generation du sel et derivation de la cle
        sel, cle = deriver_cle_complete(mot_de_passe)
        
        # 3. Chiffrement d'un message
        message_original = "Ceci est un message ultra-secret!"
        nonce, chiffre, tag = chiffrer_texte(message_original, cle)
        
        # 4. Pour dechiffrer, on recupere le sel (stocke avec les donnees)
        # et on regenere la cle
        cle_regeneree = deriver_cle(mot_de_passe, sel)
        
        # 5. Dechiffrement
        message_recupere = dechiffrer_texte(chiffre, cle_regeneree, nonce, tag)
        
        # 6. Verification
        assert message_recupere == message_original
    
    def test_workflow_avec_fichier_simule(self):
        """Simule le workflow complet avec format fichier .crypt."""
        mot_de_passe = "PasswordTest123!"
        message = "Contenu du fichier secret"
        
        # === CHIFFREMENT ===
        # Generation sel et cle
        sel, cle = deriver_cle_complete(mot_de_passe)
        
        # Chiffrement
        nonce, chiffre, tag = chiffrer_texte(message, cle)
        
        # Construction du fichier .crypt (format: salt + nonce + ciphertext + tag)
        fichier_crypt = sel + nonce + chiffre + tag
        
        # === DECHIFFREMENT ===
        # Extraction des composants
        sel_extrait = fichier_crypt[:SALT_SIZE]
        nonce_extrait = fichier_crypt[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
        tag_extrait = fichier_crypt[-TAG_SIZE:]
        chiffre_extrait = fichier_crypt[SALT_SIZE + NONCE_SIZE:-TAG_SIZE]
        
        # Regeneration de la cle
        cle_regeneree = deriver_cle(mot_de_passe, sel_extrait)
        
        # Dechiffrement
        message_recupere = dechiffrer_texte(
            chiffre_extrait,
            cle_regeneree,
            nonce_extrait,
            tag_extrait
        )
        
        assert message_recupere == message


if __name__ == "__main__":
    # Permet d'exécuter les tests directement
    pytest.main([__file__, "-v"])
