"""
Module security : Gestion du chiffrement, déchiffrement et hachage.

Ce module contient les fonctions cryptographiques utilisant AES-GCM
et PBKDF2 pour la dérivation de clés.
"""

from .key_derivation import (
    generer_sel,
    deriver_cle,
    deriver_cle_complete,
    SALT_SIZE,
    KEY_SIZE,
    ITERATIONS
)

from .crypto import (
    chiffrer_donnees,
    dechiffrer_donnees,
    chiffrer_texte,
    dechiffrer_texte,
    NONCE_SIZE,
    TAG_SIZE
)

from .password_validator import (
    calculer_entropie,
    valider_mot_de_passe,
    evaluer_force_mot_de_passe,
    afficher_recommandations
)

__all__ = [
    # Key derivation
    'generer_sel',
    'deriver_cle',
    'deriver_cle_complete',
    'SALT_SIZE',
    'KEY_SIZE',
    'ITERATIONS',
    # Crypto
    'chiffrer_donnees',
    'dechiffrer_donnees',
    'chiffrer_texte',
    'dechiffrer_texte',
    'NONCE_SIZE',
    'TAG_SIZE',
    # Password validation
    'calculer_entropie',
    'valider_mot_de_passe',
    'evaluer_force_mot_de_passe',
    'afficher_recommandations',
]
