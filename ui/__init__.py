"""
Module ui : Interface utilisateur en mode console.

Ce module contient les fonctions d'affichage et d'interaction avec
l'utilisateur via la ligne de commande.
"""

from .cli_interface import (
    afficher_bandeau,
    afficher_menu_principal,
    afficher_menu_chiffrement,
    afficher_menu_dechiffrement,
    afficher_separateur,
    afficher_succes,
    afficher_erreur,
    afficher_info,
    afficher_avertissement,
    demander_choix,
    demander_texte,
    demander_mot_de_passe,
    demander_confirmation,
    afficher_force_mot_de_passe,
    afficher_progression,
    afficher_fichier_genere,
    afficher_message_sortie,
    nettoyer_ecran,
    attendre_appui_touche,
    afficher_recommandations_mot_de_passe,
    gerer_erreur_clavier
)

__all__ = [
    'afficher_bandeau',
    'afficher_menu_principal',
    'afficher_menu_chiffrement',
    'afficher_menu_dechiffrement',
    'afficher_separateur',
    'afficher_succes',
    'afficher_erreur',
    'afficher_info',
    'afficher_avertissement',
    'demander_choix',
    'demander_texte',
    'demander_mot_de_passe',
    'demander_confirmation',
    'afficher_force_mot_de_passe',
    'afficher_progression',
    'afficher_fichier_genere',
    'afficher_message_sortie',
    'nettoyer_ecran',
    'attendre_appui_touche',
    'afficher_recommandations_mot_de_passe',
    'gerer_erreur_clavier',
]
