#!/usr/bin/env python3
"""
Module de validation de la robustesse des mots de passe.

Ce module fournit les fonctions pour évaluer la force d'un mot de passe
et s'assurer qu'il respecte les critères de sécurité minimaux.
"""

import re
import math
from typing import Tuple, List


# Critères minimaux de sécurité
LONGUEUR_MINIMALE = 8
LONGUEUR_RECOMMANDEE = 12


def calculer_entropie(mot_de_passe: str) -> float:
    """
    Calcule l'entropie d'un mot de passe en bits.
    
    L'entropie mesure le degré d'imprévisibilité du mot de passe.
    Plus l'entropie est élevée, plus le mot de passe est difficile à deviner.
    
    Args:
        mot_de_passe (str): Le mot de passe à analyser.
    
    Returns:
        float: L'entropie en bits.
    
    Formula:
        Entropie = longueur × log2(taille_alphabet)
    
    Example:
        >>> calculer_entropie("abc")
        15.51...
        >>> calculer_entropie("Abc123!@#")
        59.54...
    """
    if not mot_de_passe:
        return 0.0
    
    # Détermination de la taille de l'alphabet utilisé
    taille_alphabet = 0
    
    if re.search(r'[a-z]', mot_de_passe):  # Minuscules
        taille_alphabet += 26
    
    if re.search(r'[A-Z]', mot_de_passe):  # Majuscules
        taille_alphabet += 26
    
    if re.search(r'[0-9]', mot_de_passe):  # Chiffres
        taille_alphabet += 10
    
    if re.search(r'[^a-zA-Z0-9]', mot_de_passe):  # Caractères spéciaux
        taille_alphabet += 32  # Approximation des symboles courants
    
    # Calcul de l'entropie
    if taille_alphabet == 0:
        return 0.0
    
    entropie = len(mot_de_passe) * math.log2(taille_alphabet)
    return entropie


def valider_mot_de_passe(mot_de_passe: str, strict: bool = False) -> Tuple[bool, List[str]]:
    """
    Valide un mot de passe selon des critères de sécurité.
    
    Args:
        mot_de_passe (str): Le mot de passe à valider.
        strict (bool): Si True, applique des critères renforcés.
    
    Returns:
        Tuple[bool, List[str]]: Tuple (est_valide, liste_erreurs).
            - est_valide: True si le mot de passe est acceptable.
            - liste_erreurs: Liste des problèmes détectés.
    
    Critères normaux:
        - Au moins 8 caractères
        - Entropie minimale de 30 bits
    
    Critères stricts (mode strict=True):
        - Au moins 12 caractères
        - Au moins une majuscule
        - Au moins une minuscule
        - Au moins un chiffre
        - Au moins un caractère spécial
        - Entropie minimale de 50 bits
    
    Example:
        >>> valider_mot_de_passe("abc")
        (False, ['Le mot de passe doit contenir au moins 8 caractères', ...])
        >>> valider_mot_de_passe("MonMotDePasse123!")
        (True, [])
    """
    erreurs = []
    
    # Vérification de la longueur minimale
    longueur_min = LONGUEUR_RECOMMANDEE if strict else LONGUEUR_MINIMALE
    if len(mot_de_passe) < longueur_min:
        erreurs.append(
            f"Le mot de passe doit contenir au moins {longueur_min} caractères"
        )
    
    # Vérification de l'entropie
    entropie = calculer_entropie(mot_de_passe)
    entropie_min = 50.0 if strict else 30.0
    
    if entropie < entropie_min:
        erreurs.append(
            f"Le mot de passe est trop faible (entropie: {entropie:.1f} bits, "
            f"minimum: {entropie_min:.1f} bits)"
        )
    
    # Critères stricts supplémentaires
    if strict:
        if not re.search(r'[a-z]', mot_de_passe):
            erreurs.append("Le mot de passe doit contenir au moins une minuscule")
        
        if not re.search(r'[A-Z]', mot_de_passe):
            erreurs.append("Le mot de passe doit contenir au moins une majuscule")
        
        if not re.search(r'[0-9]', mot_de_passe):
            erreurs.append("Le mot de passe doit contenir au moins un chiffre")
        
        if not re.search(r'[^a-zA-Z0-9]', mot_de_passe):
            erreurs.append(
                "Le mot de passe doit contenir au moins un caractère spécial"
            )
    
    est_valide = len(erreurs) == 0
    return est_valide, erreurs


def evaluer_force_mot_de_passe(mot_de_passe: str) -> str:
    """
    Évalue la force d'un mot de passe et retourne un niveau descriptif.
    
    Args:
        mot_de_passe (str): Le mot de passe à évaluer.
    
    Returns:
        str: Niveau de force ("Tres faible", "Faible", "Moyen", "Fort", "Tres fort").
    
    Example:
        >>> evaluer_force_mot_de_passe("abc")
        'Tres faible'
        >>> evaluer_force_mot_de_passe("MonMotDePasse123!")
        'Fort'
    """
    entropie = calculer_entropie(mot_de_passe)
    
    if entropie < 28:
        return "Tres faible"
    elif entropie < 36:
        return "Faible"
    elif entropie < 50:
        return "Moyen"
    elif entropie < 70:
        return "Fort"
    else:
        return "Tres fort"


def afficher_recommandations() -> str:
    """
    Retourne des recommandations pour créer un mot de passe robuste.
    
    Returns:
        str: Texte avec les recommandations.
    """
    return f"""
╔══════════════════════════════════════════════════════════════╗
║  RECOMMANDATIONS POUR UN MOT DE PASSE ROBUSTE                ║
╠══════════════════════════════════════════════════════════════╣
║  • Au moins {LONGUEUR_RECOMMANDEE} caractères                                   ║
║  • Mélange de majuscules et minuscules                       ║
║  • Inclusion de chiffres                                     ║
║  • Inclusion de caractères spéciaux (!@#$%^&*...)            ║
║  • Éviter les mots du dictionnaire                           ║
║  • Éviter les informations personnelles                      ║
║  • Utiliser une phrase de passe (passphrase)                 ║
║                                                              ║
║  Exemple: "J'aime.Les.Croissants.2026!"                     ║
╚══════════════════════════════════════════════════════════════╝
"""
