#!/usr/bin/env python3
"""
Module de manipulation sécurisée des fichiers.

Ce module fournit les fonctions pour lire et écrire des fichiers de manière
sécurisée, avec protection contre les attaques par injection de chemin.
"""

import os
from pathlib import Path
from typing import Optional, Tuple


# Extensions utilisées par GuardiaBox
EXTENSION_CHIFFRE = ".crypt"
EXTENSION_DECHIFFRE = ".decrypt"


class PathTraversalError(Exception):
    """Exception levée lors d'une tentative d'injection de chemin."""
    pass


class FileOperationError(Exception):
    """Exception levée lors d'une erreur d'opération sur fichier."""
    pass


def valider_chemin(chemin: str, repertoire_base: Optional[str] = None) -> Path:
    """
    Valide un chemin de fichier et empêche les attaques par injection de chemin.
    
    Cette fonction protège contre les tentatives d'accès à des fichiers en dehors
    du répertoire autorisé via des patterns comme "../../../etc/passwd".
    
    Args:
        chemin (str): Le chemin du fichier à valider.
        repertoire_base (Optional[str]): Le répertoire de base autorisé.
            Si None, utilise le répertoire courant.
    
    Returns:
        Path: Le chemin validé et résolu.
    
    Raises:
        PathTraversalError: Si le chemin tente d'accéder en dehors
            du répertoire autorisé.
        ValueError: Si le chemin est vide ou invalide.
    
    Example:
        >>> valider_chemin("fichier.txt")
        PosixPath('.../fichier.txt')
        >>> valider_chemin("../../etc/passwd")  # Lève PathTraversalError
    """
    if not chemin or not isinstance(chemin, str):
        raise ValueError("Le chemin doit être une chaîne de caractères non vide")
    
    # Définir le répertoire de base
    if repertoire_base is None:
        repertoire_base = os.getcwd()
    
    base_path = Path(repertoire_base).resolve()
    
    # Résoudre le chemin complet (résout les "..", ".", liens symboliques)
    try:
        chemin_complet = (base_path / chemin).resolve()
    except (OSError, RuntimeError) as e:
        raise PathTraversalError(f"Chemin invalide ou inaccessible : {e}")
    
    # Vérifier que le chemin résolu est bien dans le répertoire de base
    try:
        chemin_complet.relative_to(base_path)
    except ValueError:
        raise PathTraversalError(
            f"Tentative d'accès en dehors du répertoire autorisé détectée : {chemin}"
        )
    
    return chemin_complet


def verifier_existence_fichier(chemin: str) -> bool:
    """
    Vérifie si un fichier existe.
    
    Args:
        chemin (str): Le chemin du fichier à vérifier.
    
    Returns:
        bool: True si le fichier existe, False sinon.
    
    Example:
        >>> verifier_existence_fichier("fichier_existant.txt")
        True
        >>> verifier_existence_fichier("fichier_inexistant.txt")
        False
    """
    try:
        chemin_valide = valider_chemin(chemin)
        return chemin_valide.exists() and chemin_valide.is_file()
    except (PathTraversalError, ValueError):
        return False


def lire_fichier_binaire(chemin: str) -> bytes:
    """
    Lit le contenu d'un fichier en mode binaire de manière sécurisée.
    
    Args:
        chemin (str): Le chemin du fichier à lire.
    
    Returns:
        bytes: Le contenu du fichier.
    
    Raises:
        PathTraversalError: Si le chemin est dangereux.
        FileNotFoundError: Si le fichier n'existe pas.
        FileOperationError: Si une erreur se produit lors de la lecture.
    
    Example:
        >>> contenu = lire_fichier_binaire("document.txt")
        >>> type(contenu)
        <class 'bytes'>
    """
    # Validation du chemin
    chemin_valide = valider_chemin(chemin)
    
    # Vérification de l'existence
    if not chemin_valide.exists():
        raise FileNotFoundError(f"Le fichier n'existe pas : {chemin}")
    
    if not chemin_valide.is_file():
        raise FileOperationError(f"Le chemin ne pointe pas vers un fichier : {chemin}")
    
    # Lecture sécurisée
    try:
        with open(chemin_valide, 'rb') as f:
            contenu = f.read()
        return contenu
    except PermissionError:
        raise FileOperationError(f"Permission refusée pour lire le fichier : {chemin}")
    except OSError as e:
        raise FileOperationError(f"Erreur lors de la lecture du fichier : {e}")


def lire_fichier_texte(chemin: str, encodage: str = 'utf-8') -> str:
    """
    Lit le contenu d'un fichier texte de manière sécurisée.
    
    Args:
        chemin (str): Le chemin du fichier à lire.
        encodage (str): L'encodage du fichier (défaut: utf-8).
    
    Returns:
        str: Le contenu du fichier.
    
    Raises:
        PathTraversalError: Si le chemin est dangereux.
        FileNotFoundError: Si le fichier n'existe pas.
        FileOperationError: Si une erreur se produit lors de la lecture.
    
    Example:
        >>> texte = lire_fichier_texte("message.txt")
        >>> type(texte)
        <class 'str'>
    """
    contenu_binaire = lire_fichier_binaire(chemin)
    
    try:
        return contenu_binaire.decode(encodage)
    except UnicodeDecodeError as e:
        raise FileOperationError(
            f"Erreur de décodage du fichier (encodage: {encodage}) : {e}"
        )


def ecrire_fichier_binaire(chemin: str, contenu: bytes, ecraser: bool = False) -> None:
    """
    Écrit du contenu binaire dans un fichier de manière sécurisée.
    
    Args:
        chemin (str): Le chemin du fichier à écrire.
        contenu (bytes): Le contenu à écrire.
        ecraser (bool): Si True, écrase le fichier s'il existe déjà.
    
    Raises:
        PathTraversalError: Si le chemin est dangereux.
        FileExistsError: Si le fichier existe et ecraser=False.
        FileOperationError: Si une erreur se produit lors de l'écriture.
        TypeError: Si le contenu n'est pas de type bytes.
    
    Example:
        >>> ecrire_fichier_binaire("output.bin", b"donnees", ecraser=True)
    """
    if not isinstance(contenu, bytes):
        raise TypeError("Le contenu doit être de type bytes")
    
    # Validation du chemin
    chemin_valide = valider_chemin(chemin)
    
    # Vérification de l'existence si ecraser=False
    if chemin_valide.exists() and not ecraser:
        raise FileExistsError(
            f"Le fichier existe déjà : {chemin}. "
            f"Utilisez ecraser=True pour le remplacer."
        )
    
    # Création du répertoire parent si nécessaire
    chemin_valide.parent.mkdir(parents=True, exist_ok=True)
    
    # Écriture sécurisée
    try:
        with open(chemin_valide, 'wb') as f:
            f.write(contenu)
    except PermissionError:
        raise FileOperationError(
            f"Permission refusée pour écrire le fichier : {chemin}"
        )
    except OSError as e:
        raise FileOperationError(f"Erreur lors de l'écriture du fichier : {e}")


def ecrire_fichier_texte(
    chemin: str,
    contenu: str,
    ecraser: bool = False,
    encodage: str = 'utf-8'
) -> None:
    """
    Écrit du contenu texte dans un fichier de manière sécurisée.
    
    Args:
        chemin (str): Le chemin du fichier à écrire.
        contenu (str): Le contenu à écrire.
        ecraser (bool): Si True, écrase le fichier s'il existe déjà.
        encodage (str): L'encodage du fichier (défaut: utf-8).
    
    Raises:
        PathTraversalError: Si le chemin est dangereux.
        FileExistsError: Si le fichier existe et ecraser=False.
        FileOperationError: Si une erreur se produit lors de l'écriture.
        TypeError: Si le contenu n'est pas de type str.
    
    Example:
        >>> ecrire_fichier_texte("message.txt", "Hello World!", ecraser=True)
    """
    if not isinstance(contenu, str):
        raise TypeError("Le contenu doit être de type str")
    
    try:
        contenu_binaire = contenu.encode(encodage)
    except UnicodeEncodeError as e:
        raise FileOperationError(f"Erreur d'encodage du contenu : {e}")
    
    ecrire_fichier_binaire(chemin, contenu_binaire, ecraser)


def generer_nom_fichier_chiffre(chemin_original: str) -> str:
    """
    Génère le nom du fichier chiffré à partir du fichier original.
    
    Args:
        chemin_original (str): Le chemin du fichier original.
    
    Returns:
        str: Le nom du fichier chiffré (avec extension .crypt).
    
    Example:
        >>> generer_nom_fichier_chiffre("document.txt")
        'document.txt.crypt'
        >>> generer_nom_fichier_chiffre("fichier.pdf")
        'fichier.pdf.crypt'
    """
    return chemin_original + EXTENSION_CHIFFRE


def generer_nom_fichier_dechiffre(chemin_chiffre: str) -> str:
    """
    Génère le nom du fichier déchiffré à partir du fichier chiffré.
    
    Args:
        chemin_chiffre (str): Le chemin du fichier chiffré.
    
    Returns:
        str: Le nom du fichier déchiffré.
    
    Example:
        >>> generer_nom_fichier_dechiffre("document.txt.crypt")
        'document.txt.decrypt'
        >>> generer_nom_fichier_dechiffre("fichier.pdf.crypt")
        'fichier.pdf.decrypt'
    """
    # Si le fichier se termine par .crypt, on le remplace par .decrypt
    if chemin_chiffre.endswith(EXTENSION_CHIFFRE):
        base = chemin_chiffre[:-len(EXTENSION_CHIFFRE)]
        return base + EXTENSION_DECHIFFRE
    else:
        # Sinon on ajoute simplement .decrypt
        return chemin_chiffre + EXTENSION_DECHIFFRE


def obtenir_taille_fichier(chemin: str) -> int:
    """
    Obtient la taille d'un fichier en octets.
    
    Args:
        chemin (str): Le chemin du fichier.
    
    Returns:
        int: La taille du fichier en octets.
    
    Raises:
        PathTraversalError: Si le chemin est dangereux.
        FileNotFoundError: Si le fichier n'existe pas.
    
    Example:
        >>> taille = obtenir_taille_fichier("document.txt")
        >>> taille > 0
        True
    """
    chemin_valide = valider_chemin(chemin)
    
    if not chemin_valide.exists():
        raise FileNotFoundError(f"Le fichier n'existe pas : {chemin}")
    
    return chemin_valide.stat().st_size


def supprimer_fichier(chemin: str, securise: bool = False) -> None:
    """
    Supprime un fichier de manière sécurisée.
    
    Args:
        chemin (str): Le chemin du fichier à supprimer.
        securise (bool): Si True, écrase le fichier avec des données aléatoires
            avant suppression (suppression sécurisée).
    
    Raises:
        PathTraversalError: Si le chemin est dangereux.
        FileNotFoundError: Si le fichier n'existe pas.
        FileOperationError: Si une erreur se produit lors de la suppression.
    
    Example:
        >>> supprimer_fichier("fichier_temporaire.txt")
    """
    chemin_valide = valider_chemin(chemin)
    
    if not chemin_valide.exists():
        raise FileNotFoundError(f"Le fichier n'existe pas : {chemin}")
    
    # Suppression sécurisée (écrasement avant suppression)
    if securise:
        try:
            taille = chemin_valide.stat().st_size
            # Écraser avec des données aléatoires (3 passes)
            for _ in range(3):
                with open(chemin_valide, 'wb') as f:
                    f.write(os.urandom(taille))
        except OSError as e:
            raise FileOperationError(
                f"Erreur lors de l'écrasement sécurisé : {e}"
            )
    
    # Suppression du fichier
    try:
        chemin_valide.unlink()
    except PermissionError:
        raise FileOperationError(
            f"Permission refusée pour supprimer le fichier : {chemin}"
        )
    except OSError as e:
        raise FileOperationError(f"Erreur lors de la suppression du fichier : {e}")
