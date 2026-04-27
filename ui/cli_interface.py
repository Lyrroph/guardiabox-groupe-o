#!/usr/bin/env python3
"""
Module d'interface utilisateur en mode console.

Ce module fournit les fonctions pour interagir avec l'utilisateur
via la ligne de commande de manière claire et sécurisée.
"""

import sys
import getpass
from typing import Tuple, Optional


def afficher_bandeau():
    """Affiche le bandeau de l'application."""
    print("\n" + "╔" + "═" * 68 + "╗")
    print("║" + " " * 24 + "GUARDIABOX" + " " * 34 + "║")
    print("║" + " " * 17 + "Coffre-fort numérique" + " " * 29 + "║")
    print("╚" + "═" * 68 + "╝")


def afficher_menu_principal():
    """Affiche le menu principal de l'application."""
    print("\n" + "┌" + "─" * 68 + "┐")
    print("│  [1] Chiffrer un fichier ou un message" + " " * 29 + "│")
    print("│  [2] Déchiffrer un fichier ou un message" + " " * 27 + "│")
    print("│  [3] Quitter" + " " * 55 + "│")
    print("└" + "─" * 68 + "┘")


def afficher_menu_chiffrement():
    """Affiche le sous-menu de chiffrement."""
    print("\n" + "┌" + "─" * 68 + "┐")
    print("│  CHIFFREMENT" + " " * 55 + "│")
    print("│  [1] Chiffrer un fichier existant" + " " * 34 + "│")
    print("│  [2] Chiffrer un message texte" + " " * 37 + "│")
    print("│  [3] Retour au menu principal" + " " * 38 + "│")
    print("└" + "─" * 68 + "┘")


def afficher_menu_dechiffrement():
    """Affiche le sous-menu de déchiffrement."""
    print("\n" + "┌" + "─" * 68 + "┐")
    print("│  DÉCHIFFREMENT" + " " * 53 + "│")
    print("│  [1] Déchiffrer un fichier (.crypt)" + " " * 32 + "│")
    print("│  [2] Afficher le contenu d'un message chiffré" + " " * 21 + "│")
    print("│  [3] Retour au menu principal" + " " * 38 + "│")
    print("└" + "─" * 68 + "┘")


def afficher_separateur():
    """Affiche un séparateur visuel."""
    print("─" * 70)


def afficher_succes(message: str):
    """
    Affiche un message de succès.
    
    Args:
        message (str): Le message à afficher.
    """
    print(f"\n[OK] {message}")


def afficher_erreur(message: str):
    """
    Affiche un message d'erreur.
    
    Args:
        message (str): Le message d'erreur à afficher.
    """
    print(f"\n✗ ERREUR: {message}")


def afficher_info(message: str):
    """
    Affiche un message d'information.
    
    Args:
        message (str): Le message d'information à afficher.
    """
    print(f"\n[INFO] {message}")


def afficher_avertissement(message: str):
    """
    Affiche un message d'avertissement.
    
    Args:
        message (str): Le message d'avertissement à afficher.
    """
    print(f"\n[ATTENTION] {message}")


def demander_choix(prompt: str = "Votre choix") -> str:
    """
    Demande un choix à l'utilisateur.
    
    Args:
        prompt (str): Le texte du prompt.
    
    Returns:
        str: Le choix de l'utilisateur (trimé).
    """
    reponse = input(f"\n{prompt}: ").strip()
    return reponse


def demander_texte(prompt: str, vide_autorise: bool = False) -> Optional[str]:
    """
    Demande une saisie textuelle à l'utilisateur.
    
    Args:
        prompt (str): Le texte du prompt.
        vide_autorise (bool): Si False, redemande tant que la réponse est vide.
    
    Returns:
        Optional[str]: La saisie de l'utilisateur, ou None si annulée.
    """
    while True:
        reponse = input(f"\n{prompt}: ").strip()
        
        if reponse or vide_autorise:
            return reponse
        
        afficher_erreur("La saisie ne peut pas être vide. Réessayez.")


def demander_mot_de_passe(
    prompt: str = "Mot de passe",
    confirmer: bool = False
) -> Optional[str]:
    """
    Demande un mot de passe à l'utilisateur de manière sécurisée.
    
    Args:
        prompt (str): Le texte du prompt.
        confirmer (bool): Si True, demande une confirmation du mot de passe.
    
    Returns:
        Optional[str]: Le mot de passe saisi, ou None si annulé.
    """
    while True:
        mot_de_passe = getpass.getpass(f"\n{prompt}: ")
        
        if not mot_de_passe:
            afficher_erreur("Le mot de passe ne peut pas être vide.")
            continue
        
        if confirmer:
            confirmation = getpass.getpass("\nConfirmez le mot de passe: ")
            
            if mot_de_passe != confirmation:
                afficher_erreur("Les mots de passe ne correspondent pas. Réessayez.")
                continue
        
        return mot_de_passe


def demander_confirmation(prompt: str = "Êtes-vous sûr ?") -> bool:
    """
    Demande une confirmation à l'utilisateur (Oui/Non).
    
    Args:
        prompt (str): Le texte du prompt.
    
    Returns:
        bool: True si l'utilisateur confirme (o/oui/y/yes), False sinon.
    """
    reponse = input(f"\n{prompt} [o/n]: ").strip().lower()
    return reponse in ['o', 'oui', 'y', 'yes']


def afficher_force_mot_de_passe(mot_de_passe: str):
    """
    Affiche la force d'un mot de passe avec une barre visuelle.
    
    Args:
        mot_de_passe (str): Le mot de passe à évaluer.
    """
    try:
        from security import evaluer_force_mot_de_passe, calculer_entropie
        
        force = evaluer_force_mot_de_passe(mot_de_passe)
        entropie = calculer_entropie(mot_de_passe)
        
        # Mapping des forces vers des couleurs/symboles
        symboles = {
            "Tres faible": "░░░░░",
            "Faible": "▒░░░░",
            "Moyen": "▒▒▒░░",
            "Fort": "▓▓▓▓░",
            "Tres fort": "█████"
        }
        
        barre = symboles.get(force, "░░░░░")
        
        print(f"\nForce du mot de passe: {force} [{barre}]")
        print(f"Entropie: {entropie:.1f} bits")
    
    except ImportError:
        pass  # Module security non disponible


def afficher_progression(etape: str):
    """
    Affiche une étape de progression.
    
    Args:
        etape (str): La description de l'étape.
    """
    print(f"  → {etape}...")


def afficher_fichier_genere(chemin: str, taille: int = None):
    """
    Affiche les informations sur un fichier généré.
    
    Args:
        chemin (str): Le chemin du fichier généré.
        taille (int, optional): La taille du fichier en octets.
    """
    print(f"\nFichier généré: {chemin}")
    
    if taille is not None:
        if taille < 1024:
            print(f"   Taille: {taille} octets")
        elif taille < 1024 * 1024:
            print(f"   Taille: {taille / 1024:.2f} Ko")
        else:
            print(f"   Taille: {taille / (1024 * 1024):.2f} Mo")


def afficher_message_sortie():
    """Affiche le message de sortie de l'application."""
    print("\n" + "╔" + "═" * 68 + "╗")
    print("║" + " " * 15 + "Merci d'avoir utilisé GuardiaBox !" + " " * 18 + "║")
    print("║" + " " * 26 + "À bientôt !" + " " * 31 + "║")
    print("╚" + "═" * 68 + "╝\n")


def nettoyer_ecran():
    """Nettoie l'écran de la console (optionnel)."""
    import os
    
    # Windows
    if os.name == 'nt':
        os.system('cls')
    # Unix/Linux/Mac
    else:
        os.system('clear')


def attendre_appui_touche():
    """Attend que l'utilisateur appuie sur Entrée."""
    input("\nAppuyez sur Entrée pour continuer...")


def afficher_recommandations_mot_de_passe():
    """Affiche les recommandations pour créer un mot de passe robuste."""
    try:
        from security import afficher_recommandations
        print(afficher_recommandations())
    except ImportError:
        print("""
╔══════════════════════════════════════════════════════════════╗
║  RECOMMANDATIONS POUR UN MOT DE PASSE ROBUSTE                ║
╠══════════════════════════════════════════════════════════════╣
║  • Au moins 12 caractères                                    ║
║  • Mélange de majuscules et minuscules                       ║
║  • Inclusion de chiffres                                     ║
║  • Inclusion de caractères spéciaux (!@#$%^&*...)            ║
║  • Éviter les mots du dictionnaire                           ║
║  • Éviter les informations personnelles                      ║
║  • Utiliser une phrase de passe (passphrase)                 ║
║                                                              ║
║  Exemple: "J'aime.Les.Croissants.2026!"                     ║
╚══════════════════════════════════════════════════════════════╝
        """)


def gerer_erreur_clavier():
    """Gère une interruption clavier (Ctrl+C) proprement."""
    print("\n\n[INTERRUPTION] Ctrl+C détecté")
    afficher_message_sortie()
    sys.exit(0)
