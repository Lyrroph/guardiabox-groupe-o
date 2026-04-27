#!/usr/bin/env python3
"""
Module de chiffrement et déchiffrement de fichiers.

Ce module combine les fonctionnalités de manipulation de fichiers
et les opérations cryptographiques pour chiffrer/déchiffrer des fichiers complets.
"""

import sys
import os

# Ajout du répertoire parent pour les imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from typing import Tuple
from security import (
    deriver_cle_complete,
    deriver_cle,
    chiffrer_donnees,
    dechiffrer_donnees,
    SALT_SIZE,
    NONCE_SIZE,
    TAG_SIZE
)
from .file_operations import (
    lire_fichier_binaire,
    lire_fichier_texte,
    ecrire_fichier_binaire,
    ecrire_fichier_texte,
    generer_nom_fichier_chiffre,
    generer_nom_fichier_dechiffre,
    verifier_existence_fichier,
    EXTENSION_CHIFFRE
)


class ChiffrementFichierError(Exception):
    """Exception levée lors d'une erreur de chiffrement de fichier."""
    pass


class DechiffrementFichierError(Exception):
    """Exception levée lors d'une erreur de déchiffrement de fichier."""
    pass


def chiffrer_fichier(
    chemin_fichier: str,
    mot_de_passe: str,
    chemin_sortie: str = None
) -> str:
    """
    Chiffre un fichier avec AES-256-GCM.
    
    Le fichier chiffré contient : salt + nonce + ciphertext + tag
    
    Args:
        chemin_fichier (str): Le chemin du fichier à chiffrer.
        mot_de_passe (str): Le mot de passe pour le chiffrement.
        chemin_sortie (str, optional): Le chemin du fichier de sortie.
            Si None, ajoute l'extension .crypt au nom original.
    
    Returns:
        str: Le chemin du fichier chiffré créé.
    
    Raises:
        FileNotFoundError: Si le fichier source n'existe pas.
        ChiffrementFichierError: Si une erreur se produit lors du chiffrement.
    
    Example:
        >>> chiffrer_fichier("document.txt", "MotDePasse123!")
        'document.txt.crypt'
    """
    # Vérification de l'existence du fichier
    if not verifier_existence_fichier(chemin_fichier):
        raise FileNotFoundError(f"Le fichier n'existe pas : {chemin_fichier}")
    
    try:
        # Lecture du fichier original
        donnees_originales = lire_fichier_binaire(chemin_fichier)
        
        # Génération du sel et dérivation de la clé
        sel, cle = deriver_cle_complete(mot_de_passe)
        
        # Chiffrement des données
        nonce, donnees_chiffrees, tag = chiffrer_donnees(donnees_originales, cle)
        
        # Construction du fichier .crypt : salt + nonce + ciphertext + tag
        fichier_crypt = sel + nonce + donnees_chiffrees + tag
        
        # Détermination du nom de fichier de sortie
        if chemin_sortie is None:
            chemin_sortie = generer_nom_fichier_chiffre(chemin_fichier)
        
        # Écriture du fichier chiffré
        ecrire_fichier_binaire(chemin_sortie, fichier_crypt, ecraser=True)
        
        return chemin_sortie
    
    except Exception as e:
        raise ChiffrementFichierError(
            f"Erreur lors du chiffrement du fichier : {e}"
        ) from e


def dechiffrer_fichier(
    chemin_fichier_chiffre: str,
    mot_de_passe: str,
    chemin_sortie: str = None
) -> str:
    """
    Déchiffre un fichier chiffré avec AES-256-GCM.
    
    Args:
        chemin_fichier_chiffre (str): Le chemin du fichier chiffré (.crypt).
        mot_de_passe (str): Le mot de passe pour le déchiffrement.
        chemin_sortie (str, optional): Le chemin du fichier de sortie.
            Si None, remplace .crypt par .decrypt.
    
    Returns:
        str: Le chemin du fichier déchiffré créé.
    
    Raises:
        FileNotFoundError: Si le fichier chiffré n'existe pas.
        DechiffrementFichierError: Si une erreur se produit lors du déchiffrement
            (mauvais mot de passe, fichier corrompu, etc.).
    
    Example:
        >>> dechiffrer_fichier("document.txt.crypt", "MotDePasse123!")
        'document.txt.decrypt'
    """
    # Vérification de l'existence du fichier
    if not verifier_existence_fichier(chemin_fichier_chiffre):
        raise FileNotFoundError(
            f"Le fichier chiffré n'existe pas : {chemin_fichier_chiffre}"
        )
    
    try:
        # Lecture du fichier chiffré
        fichier_crypt = lire_fichier_binaire(chemin_fichier_chiffre)
        
        # Vérification de la taille minimale
        taille_minimale = SALT_SIZE + NONCE_SIZE + TAG_SIZE
        if len(fichier_crypt) < taille_minimale:
            raise DechiffrementFichierError(
                f"Le fichier est trop petit pour être un fichier chiffré valide "
                f"(taille minimale : {taille_minimale} octets)"
            )
        
        # Extraction des composants : salt + nonce + ciphertext + tag
        sel = fichier_crypt[:SALT_SIZE]
        nonce = fichier_crypt[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
        tag = fichier_crypt[-TAG_SIZE:]
        donnees_chiffrees = fichier_crypt[SALT_SIZE + NONCE_SIZE:-TAG_SIZE]
        
        # Régénération de la clé à partir du mot de passe et du sel
        cle = deriver_cle(mot_de_passe, sel)
        
        # Déchiffrement des données (avec vérification d'intégrité)
        donnees_dechiffrees = dechiffrer_donnees(donnees_chiffrees, cle, nonce, tag)
        
        # Détermination du nom de fichier de sortie
        if chemin_sortie is None:
            chemin_sortie = generer_nom_fichier_dechiffre(chemin_fichier_chiffre)
        
        # Écriture du fichier déchiffré
        ecrire_fichier_binaire(chemin_sortie, donnees_dechiffrees, ecraser=True)
        
        return chemin_sortie
    
    except DechiffrementFichierError:
        # Propager l'exception sans la modifier
        raise
    
    except Exception as e:
        # Intercepter les erreurs de déchiffrement (tag invalide, etc.)
        raise DechiffrementFichierError(
            f"Erreur lors du déchiffrement du fichier : {e}. "
            f"Vérifiez que le mot de passe est correct."
        ) from e


def chiffrer_message(
    message: str,
    mot_de_passe: str,
    nom_fichier: str = "message.txt"
) -> str:
    """
    Chiffre un message texte et le sauvegarde dans un fichier .crypt.
    
    Cette fonction est une variante de chiffrer_fichier() qui accepte
    directement un message texte au lieu d'un fichier existant.
    
    Args:
        message (str): Le message à chiffrer.
        mot_de_passe (str): Le mot de passe pour le chiffrement.
        nom_fichier (str): Le nom de base du fichier (défaut: "message.txt").
    
    Returns:
        str: Le chemin du fichier chiffré créé.
    
    Raises:
        ChiffrementFichierError: Si une erreur se produit lors du chiffrement.
    
    Example:
        >>> chiffrer_message("Mon message secret", "Pass123!", "secret.txt")
        'secret.txt.crypt'
    """
    try:
        # Conversion du message en bytes
        donnees_message = message.encode('utf-8')
        
        # Génération du sel et dérivation de la clé
        sel, cle = deriver_cle_complete(mot_de_passe)
        
        # Chiffrement du message
        nonce, donnees_chiffrees, tag = chiffrer_donnees(donnees_message, cle)
        
        # Construction du fichier .crypt
        fichier_crypt = sel + nonce + donnees_chiffrees + tag
        
        # Nom du fichier de sortie
        chemin_sortie = generer_nom_fichier_chiffre(nom_fichier)
        
        # Écriture du fichier chiffré
        ecrire_fichier_binaire(chemin_sortie, fichier_crypt, ecraser=True)
        
        return chemin_sortie
    
    except Exception as e:
        raise ChiffrementFichierError(
            f"Erreur lors du chiffrement du message : {e}"
        ) from e


def dechiffrer_message(
    chemin_fichier_chiffre: str,
    mot_de_passe: str
) -> str:
    """
    Déchiffre un fichier et retourne le message en clair.
    
    Args:
        chemin_fichier_chiffre (str): Le chemin du fichier chiffré.
        mot_de_passe (str): Le mot de passe pour le déchiffrement.
    
    Returns:
        str: Le message déchiffré.
    
    Raises:
        FileNotFoundError: Si le fichier n'existe pas.
        DechiffrementFichierError: Si une erreur se produit lors du déchiffrement.
    
    Example:
        >>> message = dechiffrer_message("secret.txt.crypt", "Pass123!")
        >>> print(message)
        Mon message secret
    """
    # Vérification de l'existence
    if not verifier_existence_fichier(chemin_fichier_chiffre):
        raise FileNotFoundError(
            f"Le fichier chiffré n'existe pas : {chemin_fichier_chiffre}"
        )
    
    try:
        # Lecture du fichier chiffré
        fichier_crypt = lire_fichier_binaire(chemin_fichier_chiffre)
        
        # Vérification de la taille
        taille_minimale = SALT_SIZE + NONCE_SIZE + TAG_SIZE
        if len(fichier_crypt) < taille_minimale:
            raise DechiffrementFichierError(
                "Le fichier est trop petit pour être un fichier chiffré valide"
            )
        
        # Extraction des composants
        sel = fichier_crypt[:SALT_SIZE]
        nonce = fichier_crypt[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
        tag = fichier_crypt[-TAG_SIZE:]
        donnees_chiffrees = fichier_crypt[SALT_SIZE + NONCE_SIZE:-TAG_SIZE]
        
        # Régénération de la clé
        cle = deriver_cle(mot_de_passe, sel)
        
        # Déchiffrement
        donnees_dechiffrees = dechiffrer_donnees(donnees_chiffrees, cle, nonce, tag)
        
        # Conversion en texte
        message = donnees_dechiffrees.decode('utf-8')
        
        return message
    
    except DechiffrementFichierError:
        raise
    
    except UnicodeDecodeError:
        raise DechiffrementFichierError(
            "Le contenu déchiffré n'est pas un texte valide (problème d'encodage)"
        )
    
    except Exception as e:
        raise DechiffrementFichierError(
            f"Erreur lors du déchiffrement : {e}. "
            f"Vérifiez que le mot de passe est correct."
        ) from e
