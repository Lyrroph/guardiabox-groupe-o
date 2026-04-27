#!/usr/bin/env python3
"""
GuardiaBox GUI - Interface Graphique Complète

Diego DELGADO & Léopold CASTEL-GAY - Groupe O

Lance cette application avec: python guardiabox_gui.py
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os

# Imports des modules GuardiaBox  
from security import valider_mot_de_passe, evaluer_force_mot_de_passe, calculer_entropie
from fileio import (
    chiffrer_fichier, dechiffrer_fichier, chiffrer_message, dechiffrer_message,
    verifier_existence_fichier, obtenir_taille_fichier,
    ChiffrementFichierError, DechiffrementFichierError
)
from database import AuditLogger


class GuardiaBoxApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 GuardiaBox - Coffre-fort Numérique")
        self.root.geometry("950x780")
        self.root.resizable(True, True)
        self.root.minsize(800, 650)
        
        # Couleurs
        self.bg_color = "#2C3E50"
        self.fg_color = "white"
        
        # Initialiser le logger d'audit
        self.audit_logger = AuditLogger()
        
        self.creer_interface()
        self.centrer_fenetre()
    
    def centrer_fenetre(self):
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (950 // 2)
        y = (self.root.winfo_screenheight() // 2) - (780 // 2)
        self.root.geometry(f'950x780+{x}+{y}')
    
    def creer_interface(self):
        # === HEADER ===
        header = tk.Frame(self.root, bg=self.bg_color, height=70)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        
        tk.Label(
            header,
            text="🔐 GUARDIABOX",
            font=("Arial", 22, "bold"),
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(pady=8)
        
        tk.Label(
            header,
            text="Coffre-fort numérique sécurisé - AES-256-GCM + PBKDF2",
            font=("Arial", 9),
            bg=self.bg_color,
            fg="#95A5A6"
        ).pack()
        
        # === NOTEBOOK ===
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Onglets
        self.creer_onglet_chiffrement(notebook)
        self.creer_onglet_dechiffrement(notebook)
        self.creer_onglet_info(notebook)
    
    def creer_onglet_chiffrement(self, notebook):
        frame = tk.Frame(notebook, bg="white")
        notebook.add(frame, text="🔒 Chiffrement")
        
        container = tk.Frame(frame, bg="white")
        container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Mode
        mode_frame = tk.LabelFrame(container, text="Mode", font=("Arial", 10, "bold"), bg="white", padx=10, pady=10)
        mode_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.mode_chiffrement = tk.StringVar(value="fichier")
        tk.Radiobutton(mode_frame, text="📄 Chiffrer un fichier", variable=self.mode_chiffrement, value="fichier", bg="white", command=self.toggle_mode_chiffrement).pack(anchor=tk.W, pady=3)
        tk.Radiobutton(mode_frame, text="✉️ Chiffrer un message", variable=self.mode_chiffrement, value="message", bg="white", command=self.toggle_mode_chiffrement).pack(anchor=tk.W, pady=3)
        
        # Input
        self.input_chiffrement_frame = tk.LabelFrame(container, text="Fichier", font=("Arial", 10, "bold"), bg="white", padx=10, pady=10)
        self.input_chiffrement_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Fichier
        self.fichier_chiffrement_frame = tk.Frame(self.input_chiffrement_frame, bg="white")
        self.fichier_chiffrement_frame.pack(fill=tk.X)
        
        self.entry_fichier_chiffrement = tk.Entry(self.fichier_chiffrement_frame, font=("Arial", 10), width=50)
        self.entry_fichier_chiffrement.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        ttk.Button(self.fichier_chiffrement_frame, text="📁 Parcourir", command=self.parcourir_fichier_chiffrement).pack(side=tk.LEFT)
        
        # Message
        self.message_chiffrement_frame = tk.Frame(self.input_chiffrement_frame, bg="white")
        tk.Label(self.message_chiffrement_frame, text="Message :", bg="white", font=("Arial", 9)).pack(anchor=tk.W)
        self.text_message_chiffrement = tk.Text(self.message_chiffrement_frame, height=5, font=("Arial", 10), wrap=tk.WORD)
        self.text_message_chiffrement.pack(fill=tk.BOTH, expand=True)
        
        # Mot de passe
        mdp_frame = tk.LabelFrame(container, text="Mot de passe", font=("Arial", 10, "bold"), bg="white", padx=10, pady=10)
        mdp_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(mdp_frame, text="Mot de passe (min. 12 car., majuscule, chiffre, spécial) :", bg="white", font=("Arial", 9)).pack(anchor=tk.W)
        self.entry_mdp_chiffrement = tk.Entry(mdp_frame, font=("Arial", 10), show="●", width=50)
        self.entry_mdp_chiffrement.pack(fill=tk.X, pady=2)
        self.entry_mdp_chiffrement.bind('<KeyRelease>', self.verifier_force_mdp_chiffrement)
        
        tk.Label(mdp_frame, text="Confirmer :", bg="white", font=("Arial", 9)).pack(anchor=tk.W, pady=(8, 0))
        self.entry_mdp_confirm_chiffrement = tk.Entry(mdp_frame, font=("Arial", 10), show="●", width=50)
        self.entry_mdp_confirm_chiffrement.pack(fill=tk.X, pady=2)
        
        self.label_force_chiffrement = tk.Label(mdp_frame, text="Force : ---", font=("Arial", 9), bg="white", fg="gray")
        self.label_force_chiffrement.pack(anchor=tk.W, pady=5)
        
        self.progress_force_chiffrement = ttk.Progressbar(mdp_frame, length=400, mode='determinate')
        self.progress_force_chiffrement.pack(fill=tk.X, pady=3)
        
        self.var_afficher_mdp_chiffrement = tk.BooleanVar()
        tk.Checkbutton(mdp_frame, text="👁️ Afficher", variable=self.var_afficher_mdp_chiffrement, bg="white", command=self.toggle_afficher_mdp_chiffrement).pack(anchor=tk.W)
        
        # Bouton
        tk.Button(container, text="🔒 CHIFFRER", font=("Arial", 12, "bold"), bg="#27AE60", fg="white", command=self.chiffrer, relief=tk.FLAT, cursor="hand2").pack(pady=10, ipady=10, fill=tk.X)
    
    def creer_onglet_dechiffrement(self, notebook):
        frame = tk.Frame(notebook, bg="white")
        notebook.add(frame, text="🔓 Déchiffrement")
        
        container = tk.Frame(frame, bg="white")
        container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Fichier
        fichier_frame = tk.LabelFrame(container, text="Fichier chiffré (.crypt)", font=("Arial", 10, "bold"), bg="white", padx=10, pady=10)
        fichier_frame.pack(fill=tk.X, pady=(0, 10))
        
        fichier_select = tk.Frame(fichier_frame, bg="white")
        fichier_select.pack(fill=tk.X)
        
        self.entry_fichier_dechiffrement = tk.Entry(fichier_select, font=("Arial", 10), width=50)
        self.entry_fichier_dechiffrement.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        ttk.Button(fichier_select, text="📁 Parcourir", command=self.parcourir_fichier_dechiffrement).pack(side=tk.LEFT)
        
        # Mot de passe
        mdp_frame = tk.LabelFrame(container, text="Mot de passe", font=("Arial", 10, "bold"), bg="white", padx=10, pady=10)
        mdp_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(mdp_frame, text="Mot de passe de déchiffrement :", bg="white", font=("Arial", 9)).pack(anchor=tk.W)
        self.entry_mdp_dechiffrement = tk.Entry(mdp_frame, font=("Arial", 10), show="●", width=50)
        self.entry_mdp_dechiffrement.pack(fill=tk.X, pady=5)
        
        self.var_afficher_mdp_dechiffrement = tk.BooleanVar()
        tk.Checkbutton(mdp_frame, text="👁️ Afficher", variable=self.var_afficher_mdp_dechiffrement, bg="white", command=self.toggle_afficher_mdp_dechiffrement).pack(anchor=tk.W)
        
        # Mode de sortie
        self.mode_dechiffre = tk.StringVar(value="fichier")
        mode_frame = tk.LabelFrame(container, text="Mode de sortie", font=("Arial", 10, "bold"), bg="white", padx=10, pady=10)
        mode_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Radiobutton(mode_frame, text="💾 Créer un fichier .decrypt", variable=self.mode_dechiffre, value="fichier", bg="white").pack(anchor=tk.W, pady=3)
        tk.Radiobutton(mode_frame, text="👁️ Afficher le message", variable=self.mode_dechiffre, value="message", bg="white").pack(anchor=tk.W, pady=3)
        
        # Résultat
        self.text_resultat = tk.Text(container, height=8, font=("Courier", 9), wrap=tk.WORD, state=tk.DISABLED, bg="#F8F9FA")
        self.text_resultat.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Bouton
        tk.Button(container, text="🔓 DÉCHIFFRER", font=("Arial", 12, "bold"), bg="#3498DB", fg="white", command=self.dechiffrer, relief=tk.FLAT, cursor="hand2").pack(pady=10, ipady=10, fill=tk.X)
    
    def creer_onglet_info(self, notebook):
        frame = tk.Frame(notebook, bg="white")
        notebook.add(frame, text="ℹ️ Informations")
        
        container = tk.Frame(frame, bg="white")
        container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        text_info = tk.Text(container, font=("Arial", 10), wrap=tk.WORD, bg="white", relief=tk.FLAT)
        text_info.pack(fill=tk.BOTH, expand=True)
        
        info = """
🔐 GUARDIABOX - Coffre-fort Numérique Sécurisé

📋 FONCTIONNALITÉS
✅ Chiffrement de fichiers avec AES-256-GCM
✅ Chiffrement de messages texte
✅ Déchiffrement sécurisé avec vérification d'intégrité
✅ Validation stricte des mots de passe
✅ Protection contre les attaques (path traversal, force brute)

🔐 SPÉCIFICATIONS CRYPTOGRAPHIQUES
• Algorithme : AES-256-GCM (chiffrement authentifié)
• Dérivation de clé : PBKDF2-HMAC-SHA256 (600 000 itérations)
• Sel aléatoire : 256 bits
• Tag d'authentification : 128 bits GCM
• Format fichier : salt + nonce + ciphertext + tag

🔑 EXIGENCES MOT DE PASSE (MODE STRICT)
✅ Au moins 12 caractères
✅ Au moins une majuscule (A-Z)
✅ Au moins une minuscule (a-z)
✅ Au moins un chiffre (0-9)
✅ Au moins un caractère spécial (!@#$%^&*...)
✅ Entropie minimale : 50 bits

📄 EXTENSIONS FICHIERS
• .crypt : Fichier chiffré
• .decrypt : Fichier déchiffré

🛡️ SÉCURITÉ
• Protection d'intégrité (tag GCM détecte toute altération)
• Impossible de déchiffrer sans le bon mot de passe
• Protection contre les injections de chemin
• Validation stricte des entrées

👨‍💻 CRÉDITS
Développé par : Diego DELGADO & Léopold CASTEL-GAY
Groupe O - Bachelor 2ème année

© 2026 GuardiaBox - Projet DevSecOps
Gaming Campus - Bachelor 2ème année
"""
        text_info.insert('1.0', info)
        text_info.config(state=tk.DISABLED)
    
    # === MÉTHODES ===
    
    def toggle_mode_chiffrement(self):
        if self.mode_chiffrement.get() == "fichier":
            self.message_chiffrement_frame.pack_forget()
            self.fichier_chiffrement_frame.pack(fill=tk.X)
            self.input_chiffrement_frame.config(text="Fichier")
        else:
            self.fichier_chiffrement_frame.pack_forget()
            self.message_chiffrement_frame.pack(fill=tk.BOTH, expand=True)
            self.input_chiffrement_frame.config(text="Message")
    
    def toggle_afficher_mdp_chiffrement(self):
        show = "" if self.var_afficher_mdp_chiffrement.get() else "●"
        self.entry_mdp_chiffrement.config(show=show)
        self.entry_mdp_confirm_chiffrement.config(show=show)
    
    def toggle_afficher_mdp_dechiffrement(self):
        show = "" if self.var_afficher_mdp_dechiffrement.get() else "●"
        self.entry_mdp_dechiffrement.config(show=show)
    
    def parcourir_fichier_chiffrement(self):
        fichier = filedialog.askopenfilename(title="Sélectionner un fichier à chiffrer")
        if fichier:
            self.entry_fichier_chiffrement.delete(0, tk.END)
            self.entry_fichier_chiffrement.insert(0, fichier)
    
    def parcourir_fichier_dechiffrement(self):
        fichier = filedialog.askopenfilename(
            title="Sélectionner un fichier chiffré",
            filetypes=[("Fichiers chiffrés", "*.crypt"), ("Tous les fichiers", "*.*")]
        )
        if fichier:
            self.entry_fichier_dechiffrement.delete(0, tk.END)
            self.entry_fichier_dechiffrement.insert(0, fichier)
    
    def verifier_force_mdp_chiffrement(self, event=None):
        mdp = self.entry_mdp_chiffrement.get()
        
        if not mdp:
            self.label_force_chiffrement.config(text="Force : ---", fg="gray")
            self.progress_force_chiffrement['value'] = 0
            return
        
        force = evaluer_force_mot_de_passe(mdp)
        entropie = calculer_entropie(mdp)
        est_valide, erreurs = valider_mot_de_passe(mdp, strict=True)
        
        # Couleur selon la force
        couleurs = {
            "Tres faible": "#E74C3C",
            "Faible": "#E67E22",
            "Moyen": "#F39C12",
            "Fort": "#27AE60",
            "Tres fort": "#16A085"
        }
        
        couleur = couleurs.get(force, "gray")
        texte = f"Force : {force} | Entropie : {entropie:.1f} bits"
        
        if est_valide:
            texte += " ✓"
        else:
            texte += f" ✗ ({len(erreurs)} critères manquants)"
        
        self.label_force_chiffrement.config(text=texte, fg=couleur)
        
        # Barre de progression
        progress_map = {"Tres faible": 20, "Faible": 40, "Moyen": 60, "Fort": 80, "Tres fort": 100}
        self.progress_force_chiffrement['value'] = progress_map.get(force, 0)
    
    def chiffrer(self):
        # Xérification du mot de passe
        mdp = self.entry_mdp_chiffrement.get()
        mdp_confirm = self.entry_mdp_confirm_chiffrement.get()
        
        if not mdp:
            messagebox.showerror("Erreur", "Veuillez saisir un mot de passe.")
            return
        
        if mdp != mdp_confirm:
            messagebox.showerror("Erreur", "Les mots de passe ne correspondent pas.")
            return
        
        # VALIDATION STRICTE
        est_valide, erreurs = valider_mot_de_passe(mdp, strict=True)
        if not est_valide:
            msg = "❌ Le mot de passe ne respecte pas les critères de sécurité :\n\n"
            for erreur in erreurs:
                msg += f"• {erreur}\n"
            msg += "\n⚠️ Veuillez utiliser un mot de passe ROBUSTE !"
            messagebox.showerror("Mot de passe invalide", msg)
            return
        
        try:
            if self.mode_chiffrement.get() == "fichier":
                # Mode fichier
                fichier = self.entry_fichier_chiffrement.get()
                if not fichier:
                    messagebox.showerror("Erreur", "Veuillez sélectionner un fichier.")
                    return
                
                if not verifier_existence_fichier(fichier):
                    messagebox.showerror("Erreur", f"Le fichier '{fichier}' n'existe pas.")
                    return
                
                # Chiffrement  
                fichier_chiffre = chiffrer_fichier(fichier, mdp)
                taille = obtenir_taille_fichier(fichier_chiffre)
                
                # Enregistrer dans la BDD
                try:
                    self.audit_logger.log_encryption(fichier, taille, success=True)
                except Exception:
                    pass  # Ne pas bloquer si la BDD échoue
                
                messagebox.showinfo(
                    "✅ Succès",
                    f"Fichier chiffré avec succès !\n\n"
                    f"📄 Fichier : {os.path.basename(fichier_chiffre)}\n"
                    f"📊 Taille : {taille} octets\n"
                    f"🔐 Chiffrement : AES-256-GCM\n"
                    f"🔑 Dérivation : PBKDF2 (600k iter.)"
                )
            else:
                # Mode message
                message = self.text_message_chiffrement.get('1.0', tk.END).strip()
                if not message:
                    messagebox.showerror("Erreur", "Veuillez saisir un message.")
                    return
                
                fichier_chiffre = chiffrer_message(message, mdp, "message.txt")
                taille = obtenir_taille_fichier(fichier_chiffre)
                
                messagebox.showinfo(
                    "✅ Succès",
                    f"Message chiffré avec succès !\n\n"
                    f"📄 Fichier : {fichier_chiffre}\n"
                    f"📊 Taille : {taille} octets"
                )
        
        except Exception as e:
            messagebox.showerror("Erreur", f"Échec du chiffrement :\n{str(e)}")
    
    def dechiffrer(self):
        fichier = self.entry_fichier_dechiffrement.get()
        mdp = self.entry_mdp_dechiffrement.get()
        
        if not fichier:
            messagebox.showerror("Erreur", "Veuillez sélectionner un fichier.")
            return
        
        if not mdp:
            messagebox.showerror("Erreur", "Veuillez saisir le mot de passe.")
            return
        
        if not verifier_existence_fichier(fichier):
            messagebox.showerror("Erreur", f"Le fichier '{fichier}' n'existe pas.")
            return
        
        try:
            if self.mode_dechiffre.get() == "fichier":
                # Mode fichier
                fichier_dechiffre = dechiffrer_fichier(fichier, mdp)
                taille = obtenir_taille_fichier(fichier_dechiffre)
                
                # Enregistrer dans la BDD
                try:
                    self.audit_logger.log_decryption(fichier, success=True)
                except Exception:
                    pass  # Ne pas bloquer si la BDD échoue
                
                messagebox.showinfo(
                    "✅ Succès",
                    f"Fichier déchiffré avec succès !\n\n"
                    f"📄 Fichier : {os.path.basename(fichier_dechiffre)}\n"
                    f"📊 Taille : {taille} octets\n"
                    f"✓ Intégrité vérifiée (tag GCM)"
                )
            else:
                # Mode message
                message = dechiffrer_message(fichier, mdp)
                
                # Afficher dans la zone de texte
                self.text_resultat.config(state=tk.NORMAL)
                self.text_resultat.delete('1.0', tk.END)
                self.text_resultat.insert('1.0', f"📩 MESSAGE DÉCHIFFRÉ :\n\n{message}")
                self.text_resultat.config(state=tk.DISABLED)
                
                messagebox.showinfo("✅ Succès", "Message déchiffré et affiché ci-dessous.")
        
        except DechiffrementFichierError as e:
            messagebox.showerror(
                "Erreur de déchiffrement",
                f"Échec du déchiffrement :\n{str(e)}\n\n"
                f"⚠️ Vérifiez que le mot de passe est correct."
            )
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur inattendue :\n{str(e)}")


def main():
    root = tk.Tk()
    app = GuardiaBoxApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
