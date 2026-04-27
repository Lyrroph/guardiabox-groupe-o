#!/usr/bin/env python3
"""
GuardiaBox - Coffre-fort numérique sécurisé en ligne de commande.

Application CLI permettant de chiffrer et déchiffrer des fichiers ou
des messages de manière sécurisée en utilisant AES-GCM et PBKDF2

Diego et Léopold
Date: 20 avril 2026
"""

import sys
import os

# Imports des modules GuardiaBox
from ui import (
    afficher_bandeau,
    afficher_menu_principal,
    afficher_menu_chiffrement,
    afficher_menu_dechiffrement,
    afficher_succes,
    afficher_erreur,
    afficher_info,
    afficher_progression,
    afficher_fichier_genere,
    afficher_message_sortie,
    afficher_force_mot_de_passe,
    afficher_recommandations_mot_de_passe,
    demander_choix,
    demander_texte,
    demander_mot_de_passe,
    demander_confirmation,
    gerer_erreur_clavier
)

from fileio import (
    chiffrer_fichier,
    dechiffrer_fichier,
    chiffrer_message,
    dechiffrer_message,
    verifier_existence_fichier,
    obtenir_taille_fichier,
    ChiffrementFichierError,
    DechiffrementFichierError,
    PathTraversalError
)

from security import (
    valider_mot_de_passe,
    evaluer_force_mot_de_passe
)


def demander_mot_de_passe_valide(prompt: str, mode_strict: bool = True) -> str:
    """
    Demande un mot de passe et boucle jusqu'à ce qu'il soit valide.
    
    Args:
        prompt (str): Le message à afficher
        mode_strict (bool): Si True, applique les critères stricts (12 car, spéciaux, etc.)
    
    Returns:
        str: Un mot de passe valide
    """
    while True:
        # Demander le mot de passe avec confirmation
        mot_de_passe = demander_mot_de_passe(prompt, confirmer=True)
        
        if not mot_de_passe:
            return None
        
        # Valider le mot de passe
        est_valide, erreurs = valider_mot_de_passe(mot_de_passe, strict=mode_strict)
        
        if est_valide:
            # Afficher la force du mot de passe
            afficher_force_mot_de_passe(mot_de_passe)
            return mot_de_passe
        else:
            # Afficher les erreurs
            afficher_erreur("Le mot de passe ne respecte pas les critères de sécurité:")
            for erreur in erreurs:
                print(f"  • {erreur}")
            
            print("\n[ATTENTION] Veuillez ressaisir un mot de passe respectant TOUS les critères.\n")
            # La boucle continue et redemande


def chiffrer_fichier_menu():
    """Gère le chiffrement d'un fichier existant."""
    try:
        # Demander le nom du fichier
        nom_fichier = demander_texte("Nom du fichier à chiffrer (ex: document.txt)")
        
        if not nom_fichier:
            return
        
        # Vérifier l'existence
        if not verifier_existence_fichier(nom_fichier):
            afficher_erreur(f"Le fichier '{nom_fichier}' n'existe pas.")
            return
        
        # Afficher les recommandations
        afficher_info("Choisissez un mot de passe robuste pour le chiffrement")
        afficher_recommandations_mot_de_passe()
        
        # Demander un mot de passe VALIDE (boucle jusqu'à ce qu'il soit valide)
        mot_de_passe = demander_mot_de_passe_valide(
            "Mot de passe de chiffrement",
            mode_strict=True
        )
        
        if not mot_de_passe:
            return
        
        # Chiffrement
        afficher_info("Chiffrement en cours...")
        afficher_progression("Lecture du fichier")
        afficher_progression("Génération de la clé (PBKDF2-HMAC-SHA256)")
        afficher_progression("Chiffrement (AES-256-GCM)")
        
        fichier_chiffre = chiffrer_fichier(nom_fichier, mot_de_passe)
        
        taille = obtenir_taille_fichier(fichier_chiffre)
        afficher_succes("Fichier chiffré avec succès !")
        afficher_fichier_genere(fichier_chiffre, taille)
        
    except PathTraversalError as e:
        afficher_erreur(f"Tentative d'accès non autorisé détectée: {e}")
    except ChiffrementFichierError as e:
        afficher_erreur(f"Échec du chiffrement: {e}")
    except Exception as e:
        afficher_erreur(f"Erreur inattendue: {e}")


def chiffrer_message_menu():
    """Gère le chiffrement d'un message texte."""
    try:
        # Demander le message
        afficher_info("Entrez le message à chiffrer (Ctrl+C pour annuler)")
        message = demander_texte("Message")
        
        if not message:
            return
        
        # Demander un nom de fichier (optionnel)
        nom_base = demander_texte(
            "Nom de base pour le fichier (défaut: message.txt)",
            vide_autorise=True
        )
        
        if not nom_base:
            nom_base = "message.txt"
        
        # Afficher les recommandations
        afficher_info("Choisissez un mot de passe robuste")
        afficher_recommandations_mot_de_passe()
        
        # Demander un mot de passe VALIDE (boucle jusqu'à ce qu'il soit valide)
        mot_de_passe = demander_mot_de_passe_valide(
            "Mot de passe de chiffrement",
            mode_strict=True
        )
        
        if not mot_de_passe:
            return
    except Exception as e:
        afficher_erreur(f"Erreur inattendue: {e}")


def dechiffrer_fichier_menu():
    """Gère le déchiffrement d'un fichier .crypt."""
    try:
        # Demander le nom du fichier
        nom_fichier = demander_texte("Nom du fichier à déchiffrer (ex: document.txt.crypt)")
        
        if not nom_fichier:
            return
        
        # Vérifier l'existence
        if not verifier_existence_fichier(nom_fichier):
            afficher_erreur(f"Le fichier '{nom_fichier}' n'existe pas.")
            return
        
        # Demander le mot de passe
        mot_de_passe = demander_mot_de_passe("Mot de passe de déchiffrement")
        
        if not mot_de_passe:
            return
        
        # Déchiffrement
        afficher_info("Déchiffrement en cours...")
        afficher_progression("Lecture du fichier chiffré")
        afficher_progression("Extraction du sel et du nonce")
        afficher_progression("Régénération de la clé")
        afficher_progression("Déchiffrement et vérification d'intégrité")
        
        fichier_dechiffre = dechiffrer_fichier(nom_fichier, mot_de_passe)
        
        taille = obtenir_taille_fichier(fichier_dechiffre)
        afficher_succes("Fichier déchiffré avec succès !")
        afficher_fichier_genere(fichier_dechiffre, taille)
        
    except PathTraversalError as e:
        afficher_erreur(f"Tentative d'accès non autorisé détectée: {e}")
    except DechiffrementFichierError as e:
        afficher_erreur(f"Échec du déchiffrement: {e}")
        afficher_info("Vérifiez que le mot de passe est correct.")
    except Exception as e:
        afficher_erreur(f"Erreur inattendue: {e}")


def afficher_message_menu():
    """Gère l'affichage d'un message déchiffré."""
    try:
        # Demander le nom du fichier
        nom_fichier = demander_texte("Nom du fichier chiffré (ex: message.txt.crypt)")
        
        if not nom_fichier:
            return
        
        # Vérifier l'existence
        if not verifier_existence_fichier(nom_fichier):
            afficher_erreur(f"Le fichier '{nom_fichier}' n'existe pas.")
            return
        
        # Demander le mot de passe
        mot_de_passe = demander_mot_de_passe("Mot de passe de déchiffrement")
        
        if not mot_de_passe:
            return
        
        # Déchiffrement
        afficher_info("Déchiffrement du message...")
        
        message = dechiffrer_message(nom_fichier, mot_de_passe)
        
        afficher_succes("Message déchiffré avec succès !")
        print("\n" + "─" * 70)
        print("MESSAGE DÉCHIFFRÉ:")
        print("─" * 70)
        print(message)
        print("─" * 70)
        
    except DechiffrementFichierError as e:
        afficher_erreur(f"Échec du déchiffrement: {e}")
        afficher_info("Vérifiez que le mot de passe est correct.")
    except Exception as e:
        afficher_erreur(f"Erreur inattendue: {e}")


def menu_chiffrement():
    """Affiche le menu de chiffrement et gère les choix."""
    while True:
        afficher_menu_chiffrement()
        choix = demander_choix()
        
        if choix == "1":
            chiffrer_fichier_menu()
        elif choix == "2":
            chiffrer_message_menu()
        elif choix == "3":
            break
        else:
            afficher_erreur("Choix invalide. Veuillez saisir 1, 2 ou 3.")


def menu_dechiffrement():
    """Affiche le menu de déchiffrement et gère les choix."""
    while True:
        afficher_menu_dechiffrement()
        choix = demander_choix()
        
        if choix == "1":
            dechiffrer_fichier_menu()
        elif choix == "2":
            afficher_message_menu()
        elif choix == "3":
            break
        else:
            afficher_erreur("Choix invalide. Veuillez saisir 1, 2 ou 3.")


def quitter():
    """Quitte l'application proprement."""
    afficher_message_sortie()
    sys.exit(0)


def main():
    """Point d'entrée principal de l'application."""
    afficher_bandeau()
    
    while True:
        afficher_menu_principal()
        
        try:
            choix = demander_choix()
            
            if choix == "1":
                menu_chiffrement()
            elif choix == "2":
                menu_dechiffrement()
            elif choix == "3":
                quitter()
            else:
                afficher_erreur("Choix invalide. Veuillez saisir 1, 2 ou 3.")
        
        except KeyboardInterrupt:
            gerer_erreur_clavier()
        except Exception as e:
            afficher_erreur(f"Une erreur inattendue s'est produite : {e}")


if __name__ == "__main__":
    main()
