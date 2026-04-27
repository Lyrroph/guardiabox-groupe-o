#!/usr/bin/env python3
"""
Module de chiffrement et déchiffrement avec AES-GCM.

Ce module fournit les fonctions pour chiffrer et déchiffrer des données
en utilisant l'algorithme AES-256-GCM (Galois/Counter Mode) qui assure
à la fois la confidentialité et l'intégrité des données.
"""

import os
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


# Constantes pour AES-GCM
NONCE_SIZE = 12  # 96 bits (taille recommandée pour GCM)
KEY_SIZE = 32    # 256 bits pour AES-256
TAG_SIZE = 16    # 128 bits (taille du tag d'authentification GCM)


def chiffrer_donnees(donnees_claires: bytes, cle: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Chiffre des données avec AES-256-GCM.
    
    Args:
        donnees_claires (bytes): Les données à chiffrer.
        cle (bytes): La clé de chiffrement (32 octets pour AES-256).
    
    Returns:
        Tuple[bytes, bytes, bytes]: Tuple (nonce, donnees_chiffrees, tag).
            - nonce: Nonce aléatoire de 12 octets
            - donnees_chiffrees: Données chiffrées
            - tag: Tag d'authentification de 16 octets (intégré par AESGCM)
    
    Raises:
        ValueError: Si la clé n'a pas la bonne taille.
        TypeError: Si les types des arguments sont incorrects.
    
    Example:
        >>> from security.key_derivation import deriver_cle_complete
        >>> sel, cle = deriver_cle_complete("password")
        >>> nonce, chiffre, tag = chiffrer_donnees(b"Secret!", cle)
        >>> len(nonce), len(tag)
        (12, 16)
    """
    # Validation des entrées
    if not isinstance(donnees_claires, bytes):
        raise TypeError("Les données doivent être de type bytes")
    
    if not isinstance(cle, bytes):
        raise TypeError("La clé doit être de type bytes")
    
    if len(cle) != KEY_SIZE:
        raise ValueError(f"La clé doit faire exactement {KEY_SIZE} octets")
    
    # Génération d'un nonce aléatoire unique
    nonce = os.urandom(NONCE_SIZE)
    
    # Création de l'objet AESGCM
    aesgcm = AESGCM(cle)
    
    # Chiffrement des données (le tag est automatiquement ajouté à la fin)
    donnees_chiffrees_avec_tag = aesgcm.encrypt(nonce, donnees_claires, None)
    
    # Séparation des données chiffrées et du tag
    # AESGCM.encrypt() retourne: ciphertext || tag
    donnees_chiffrees = donnees_chiffrees_avec_tag[:-TAG_SIZE]
    tag = donnees_chiffrees_avec_tag[-TAG_SIZE:]
    
    return nonce, donnees_chiffrees, tag


def dechiffrer_donnees(
    donnees_chiffrees: bytes,
    cle: bytes,
    nonce: bytes,
    tag: bytes
) -> bytes:
    """
    Déchiffre des données avec AES-256-GCM et vérifie l'intégrité.
    
    Args:
        donnees_chiffrees (bytes): Les données chiffrées.
        cle (bytes): La clé de déchiffrement (32 octets).
        nonce (bytes): Le nonce utilisé lors du chiffrement (12 octets).
        tag (bytes): Le tag d'authentification (16 octets).
    
    Returns:
        bytes: Les données déchiffrées.
    
    Raises:
        ValueError: Si les paramètres n'ont pas les bonnes tailles.
        TypeError: Si les types des arguments sont incorrects.
        InvalidTag: Si le tag est invalide (données corrompues ou clé incorrecte).
    
    Example:
        >>> from security.key_derivation import deriver_cle_complete
        >>> sel, cle = deriver_cle_complete("password")
        >>> nonce, chiffre, tag = chiffrer_donnees(b"Secret!", cle)
        >>> dechiffre = dechiffrer_donnees(chiffre, cle, nonce, tag)
        >>> dechiffre
        b'Secret!'
    """
    # Validation des entrées
    if not isinstance(donnees_chiffrees, bytes):
        raise TypeError("Les données chiffrées doivent être de type bytes")
    
    if not isinstance(cle, bytes):
        raise TypeError("La clé doit être de type bytes")
    
    if not isinstance(nonce, bytes):
        raise TypeError("Le nonce doit être de type bytes")
    
    if not isinstance(tag, bytes):
        raise TypeError("Le tag doit être de type bytes")
    
    if len(cle) != KEY_SIZE:
        raise ValueError(f"La clé doit faire exactement {KEY_SIZE} octets")
    
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"Le nonce doit faire exactement {NONCE_SIZE} octets")
    
    if len(tag) != TAG_SIZE:
        raise ValueError(f"Le tag doit faire exactement {TAG_SIZE} octets")
    
    # Création de l'objet AESGCM
    aesgcm = AESGCM(cle)
    
    # Reconstruction du ciphertext complet (données + tag)
    donnees_chiffrees_avec_tag = donnees_chiffrees + tag
    
    try:
        # Déchiffrement et vérification du tag
        donnees_claires = aesgcm.decrypt(nonce, donnees_chiffrees_avec_tag, None)
        return donnees_claires
    
    except InvalidTag:
        raise InvalidTag(
            "Échec de l'authentification : le tag est invalide. "
            "Les données ont peut-être été corrompues ou le mot de passe est incorrect."
        )


def chiffrer_texte(texte: str, cle: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Chiffre un texte (string) avec AES-256-GCM.
    
    Fonction utilitaire qui encode le texte en UTF-8 avant le chiffrement.
    
    Args:
        texte (str): Le texte à chiffrer.
        cle (bytes): La clé de chiffrement (32 octets).
    
    Returns:
        Tuple[bytes, bytes, bytes]: Tuple (nonce, donnees_chiffrees, tag).
    
    Example:
        >>> from security.key_derivation import deriver_cle_complete
        >>> sel, cle = deriver_cle_complete("password")
        >>> nonce, chiffre, tag = chiffrer_texte("Message secret", cle)
    """
    if not isinstance(texte, str):
        raise TypeError("Le texte doit être une chaîne de caractères")
    
    donnees_claires = texte.encode('utf-8')
    return chiffrer_donnees(donnees_claires, cle)


def dechiffrer_texte(
    donnees_chiffrees: bytes,
    cle: bytes,
    nonce: bytes,
    tag: bytes
) -> str:
    """
    Déchiffre des données et retourne un texte (string).
    
    Fonction utilitaire qui décode les données déchiffrées en UTF-8.
    
    Args:
        donnees_chiffrees (bytes): Les données chiffrées.
        cle (bytes): La clé de déchiffrement (32 octets).
        nonce (bytes): Le nonce (12 octets).
        tag (bytes): Le tag d'authentification (16 octets).
    
    Returns:
        str: Le texte déchiffré.
    
    Example:
        >>> from security.key_derivation import deriver_cle_complete
        >>> sel, cle = deriver_cle_complete("password")
        >>> nonce, chiffre, tag = chiffrer_texte("Message secret", cle)
        >>> texte = dechiffrer_texte(chiffre, cle, nonce, tag)
        >>> texte
        'Message secret'
    """
    donnees_claires = dechiffrer_donnees(donnees_chiffrees, cle, nonce, tag)
    return donnees_claires.decode('utf-8')
