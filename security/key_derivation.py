#!/usr/bin/env python3
"""
Module de dérivation de clé avec PBKDF2.

Ce module fournit les fonctions pour dériver une clé cryptographique
robuste à partir d'un mot de passe utilisateur.
"""

import os
import hashlib
from typing import Tuple


# Constantes de sécurité pour PBKDF2
SALT_SIZE = 32  # 256 bits
KEY_SIZE = 32   # 256 bits pour AES-256
ITERATIONS = 600_000  # Recommandation OWASP 2023+ pour PBKDF2-SHA256


def generer_sel() -> bytes:
    """
    Génère un sel cryptographique aléatoire.
    
    Returns:
        bytes: Sel aléatoire de 32 octets (256 bits).
    
    Example:
        >>> sel = generer_sel()
        >>> len(sel)
        32
    """
    return os.urandom(SALT_SIZE)


def deriver_cle(mot_de_passe: str, sel: bytes) -> bytes:
    """
    Dérive une clé cryptographique à partir d'un mot de passe avec PBKDF2.
    
    Args:
        mot_de_passe (str): Le mot de passe fourni par l'utilisateur.
        sel (bytes): Le sel cryptographique (doit être de 32 octets).
    
    Returns:
        bytes: Clé dérivée de 32 octets (256 bits) pour AES-256-GCM.
    
    Raises:
        ValueError: Si le sel n'a pas la bonne taille.
        TypeError: Si les types des arguments sont incorrects.
    
    Example:
        >>> sel = generer_sel()
        >>> cle = deriver_cle("MonMotDePasse!", sel)
        >>> len(cle)
        32
    """
    # Validation des entrées
    if not isinstance(mot_de_passe, str):
        raise TypeError("Le mot de passe doit être une chaîne de caractères")
    
    if not isinstance(sel, bytes):
        raise TypeError("Le sel doit être de type bytes")
    
    if len(sel) != SALT_SIZE:
        raise ValueError(f"Le sel doit faire exactement {SALT_SIZE} octets")
    
    # Conversion du mot de passe en bytes (UTF-8)
    mot_de_passe_bytes = mot_de_passe.encode('utf-8')
    
    # Dérivation de la clé avec PBKDF2-HMAC-SHA256
    cle = hashlib.pbkdf2_hmac(
        'sha256',
        mot_de_passe_bytes,
        sel,
        ITERATIONS,
        dklen=KEY_SIZE
    )
    
    return cle


def deriver_cle_complete(mot_de_passe: str) -> Tuple[bytes, bytes]:
    """
    Génère un nouveau sel et dérive une clé en une seule opération.
    
    Fonction utilitaire qui combine la génération du sel et la dérivation
    de clé pour simplifier le processus de chiffrement.
    
    Args:
        mot_de_passe (str): Le mot de passe fourni par l'utilisateur.
    
    Returns:
        Tuple[bytes, bytes]: Tuple (sel, clé_dérivée).
    
    Example:
        >>> sel, cle = deriver_cle_complete("MonMotDePasse!")
        >>> len(sel), len(cle)
        (32, 32)
    """
    sel = generer_sel()
    cle = deriver_cle(mot_de_passe, sel)
    return sel, cle
