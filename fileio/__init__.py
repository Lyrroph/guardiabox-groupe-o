"""
Module fileio : Gestion de la lecture et écriture sécurisée des fichiers.

Ce module contient les fonctions pour manipuler les fichiers de manière
sécurisée, avec protection contre les attaques par injection de chemin.
"""

from .file_operations import (
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
    PathTraversalError,
    FileOperationError,
    EXTENSION_CHIFFRE,
    EXTENSION_DECHIFFRE
)

from .crypto_file import (
    chiffrer_fichier,
    dechiffrer_fichier,
    chiffrer_message,
    dechiffrer_message,
    ChiffrementFichierError,
    DechiffrementFichierError
)

__all__ = [
    # File operations
    'valider_chemin',
    'verifier_existence_fichier',
    'lire_fichier_binaire',
    'lire_fichier_texte',
    'ecrire_fichier_binaire',
    'ecrire_fichier_texte',
    'generer_nom_fichier_chiffre',
    'generer_nom_fichier_dechiffre',
    'obtenir_taille_fichier',
    'supprimer_fichier',
    'PathTraversalError',
    'FileOperationError',
    'EXTENSION_CHIFFRE',
    'EXTENSION_DECHIFFRE',
    # Crypto file operations
    'chiffrer_fichier',
    'dechiffrer_fichier',
    'chiffrer_message',
    'dechiffrer_message',
    'ChiffrementFichierError',
    'DechiffrementFichierError',
]
