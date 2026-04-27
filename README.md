# GuardiaBox

**Application de chiffrement en ligne de commande avec interface graphique optionnelle**

Version 1.0.0 | Python 3.8+ | Projet DevSecOps

## Description

On a décidé dans le README de vous faire une présentation complète avec tout ce qu'il faut etc pour comprendre l'application et comment elle fonctionne...

Greg Mistral et Diego DELGADO

GuardiaBox est une application de chiffrement développée en Python qui utilise les standards cryptographiques actuels pour protéger les fichiers et messages : AES-256-GCM pour le chiffrement et PBKDF2 pour la dérivation de clés.

Le projet propose deux interfaces :
- **CLI (ligne de commande)** : L'interface principale, légère et puissante
- **GUI (interface graphique)** : Version bonus avec tkinter pour les utilisateurs préférant une interface visuelle

### Fonctionnalités principales

- Chiffrement et déchiffrement de fichiers (tous formats)
- Chiffrement et déchiffrement de messages texte
- Validation stricte des mots de passe (12+ caractères, complexité)
- Protection d'intégrité avec authentification AES-GCM
- Détection automatique des modifications non autorisées
- 51 tests unitaires validant la sécurité

---

## Installation

### Prérequis

- Python 3.8 ou supérieur
- Windows, Linux ou macOS
- pip pour installer les dépendances

### Étapes

1. Cloner ou télécharger le projet

2. Installer les dépendances :
   ```bash
   pip install -r requirements.txt
   ```

3. **Linux** : Rendre le script exécutable :
   ```bash
   chmod +x guardiabox
   ```

4. Vérifier l'installation avec les tests :
   ```bash
   python -m pytest tests/ -v
   ```
   Résultat attendu : `51 passed`

---

## Utilisation - Version CLI (Principale)

### Lancement

**Linux/macOS** :
```bash
cd guardiabox
python3 main.py
```

Ou utiliser le script exécutable :
```bash
./guardiabox
```

**Windows** :
```powershell
cd guardiabox
python main.py
```

### Menu principal

L'application CLI présente un menu avec 3 options :

```
╔════════════════════════════════════════════════════════════════════╗
║                        GUARDIABOX                                  ║
║                 Coffre-fort numérique                             ║
╚════════════════════════════════════════════════════════════════════╝

┌────────────────────────────────────────────────────────────────────┐
│  [1] Chiffrer un fichier ou un message                             │
│  [2] Déchiffrer un fichier ou un message                           │
│  [3] Quitter                                                       │
└────────────────────────────────────────────────────────────────────┘
```

### Exemples d'utilisation

**Chiffrer un fichier** :
1. Lancer `python main.py`
2. Choisir `[1]` puis `[1]` pour "Chiffrer un fichier"
3. Entrer le nom du fichier : `document.pdf`
4. Entrer un mot de passe fort : `MonMotDePasse2024!`
5. Le fichier `document.pdf.crypt` est créé

**Chiffrer un message** :
1. Lancer `python main.py`
2. Choisir `[1]` puis `[2]` pour "Chiffrer un message"
3. Saisir votre message
4. Entrer un mot de passe fort
5. Le fichier `message.txt.crypt` est créé

**Déchiffrer** :
1. Lancer `python main.py`
2. Choisir `[2]` pour "Déchiffrer"
3. Choisir le mode (fichier ou affichage direct)
4. Entrer le nom du fichier `.crypt`
5. Entrer le mot de passe
6. Le contenu est déchiffré

### Validation des mots de passe

L'application bloque les mots de passe faibles. Critères obligatoires :
- Minimum 12 caractères
- Au moins 1 majuscule (A-Z)
- Au moins 1 minuscule (a-z)
- Au moins 1 chiffre (0-9)
- Au moins 1 caractère spécial (!@#$%^&*...)
- Entropie minimale : 50 bits

Exemple de mot de passe valide : `MonMotDePasse2024!`

---

## Version GUI (Optionnelle)

Pour les utilisateurs préférant une interface graphique, une version avec tkinter est disponible.

### Lancement de la GUI

**Linux/macOS** :
```bash
python3 guardiabox_gui.py
```

**Windows** :
```powershell
python guardiabox_gui.py
```
Ou double-cliquer sur `LANCER_GUI.bat`

### Fonctionnalités GUI

- 3 onglets : Chiffrement, Déchiffrement, Informations
- Sélection de fichiers par dialogue système
- Barre de force du mot de passe en temps réel (rouge → vert)
- Popups pour les erreurs et confirmations
- Checkbox "Afficher le mot de passe"

Les deux versions (CLI et GUI) sont totalement compatibles : un fichier chiffré avec la CLI peut être déchiffré avec la GUI et inversement.

---

## Spécifications Techniques

### Cryptographie

| Composant | Spécification |
|-----------|---------------|
| Chiffrement | AES-256-GCM (authentifié) |
| Dérivation clé | PBKDF2-HMAC-SHA256 |
| Itérations | 600 000 (NIST 2023+) |
| Sel | 256 bits (aléatoire) |
| Nonce | 96 bits (unique par opération) |
| Tag GCM | 128 bits (authentification) |

### Format fichier chiffré

```
[32 octets SEL] + [12 octets NONCE] + [n octets CIPHERTEXT] + [16 octets TAG]
```

### Extensions

- `.crypt` : Fichier chiffré
- `.decrypt` : Fichier déchiffré

---

## Validation des Mots de Passe

L'application bloque strictement les mots de passe faibles.

### Critères obligatoires

- Minimum 12 caractères
- Au moins 1 majuscule (A-Z)
- Au moins 1 minuscule (a-z)
- Au moins 1 chiffre (0-9)
- Au moins 1 caractère spécial (!@#$%^&*...)
- Entropie minimale : 50 bits

### Indicateur de force (GUI)

| Couleur | Force | Entropie |
|---------|-------|----------|
| Rouge | Très faible | < 35 bits |
| Orange | Faible | 35-50 bits |
| Jaune | Moyen | 50-65 bits |
| Vert | Fort | > 65 bits |

---

## Tests Unitaires

### Exécution

```powershell
# Tous les tests
python -m pytest tests/ -v

# Tests de sécurité uniquement
python -m pytest tests/test_security.py -v

# Tests d'I/O uniquement
python -m pytest tests/test_fileio.py -v
```

### Couverture

- 65 tests au total
- 22 tests pour le module `security/`
- 29 tests pour le module `fileio/`
- 14 tests pour le module `database/`
- Tous les tests passent

---

## Base de Données d'Audit (Optionnelle)

GuardiaBox intègre un système de **journal d'audit sécurisé** utilisant SQLite pour tracer les opérations sans compromettre la confidentialité.

### Fonctionnalités

- **Historique des opérations** : Trace automatique des chiffrements/déchiffrements
- **Statistiques** : Nombre total d'opérations, volume chiffré
- **Métadonnées hachées** : Les noms de fichiers sont hachés en SHA-256 avant stockage
- **Aucune donnée sensible** : Les mots de passe ne sont JAMAIS stockés
- **Effacement complet** : Possibilité d'effacer tout l'historique

### Sécurité de la BDD

| Donnée | Stockage |
|--------|----------|
| Noms de fichiers | Hachés (SHA-256) |
| Mots de passe | ❌ JAMAIS stockés |
| Dates/heures | Horodatage ISO 8601 |
| Tailles de fichiers | Oui (en octets) |
| Type d'opération | encrypt / decrypt |

### Fichier de base de données

- **Nom** : `guardiabox_audit.db`
- **Emplacement** : Dossier de travail actuel
- **Format** : SQLite 3
- **Taille** : Minimale (quelques Ko)

La base de données est créée automatiquement au premier lancement et n'est **jamais commitée** dans Git (exclue par `.gitignore`).

### Principe "Zero Knowledge"

Même en cas d'accès à la base de données, un attaquant ne pourrait :
- ❌ Récupérer les mots de passe (non stockés)
- ❌ Identifier les fichiers (noms hachés)
- ❌ Lire le contenu chiffré (stocké séparément)
- ✅ Voir uniquement : nombre d'opérations et dates

---

## Architecture du Projet

```
guardiabox/
├── security/                    Module cryptographie
│   ├── key_derivation.py        PBKDF2
│   ├── crypto.py                AES-GCM
│   └── password_validator.py    Validation mots de passe
│
├── fileio/                      Module I/O sécurisé
│   ├── file_operations.py       Opérations fichiers
│   └── crypto_file.py           Chiffrement fichiers
│
├── database/                    Module audit (optionnel)
│   ├── db_manager.py            Gestionnaire SQLite
│   └── audit_log.py             Journal d'audit
│
├── ui/                          Module interface
│   └── cli_interface.py         Interface CLI
│
├── tests/                       Tests unitaires
│   ├── test_security.py         22 tests
│   ├── test_fileio.py           29 tests
│   └── test_database.py         14 tests
│
├── main.py                      Application CLI (PRINCIPALE)
├── guardiabox                   Script exécutable Linux
├── guardiabox_gui.py            Application GUI (optionnelle)
├── LANCER_GUI.bat               Raccourci GUI Windows
└── requirements.txt             Dépendances
```

---

## Sécurité et Conformité

### Standards respectés

- OWASP : Algorithmes cryptographiques recommandés
- NIST : 600 000 itérations PBKDF2 (standard 2023+)
- PEP 8 : Code Python conforme aux conventions
- DevSecOps : Tests automatisés intégrés

### Protections implémentées

- Protection contre les attaques par force brute (grâce au PBKDF2)
- Protection contre les injections de chemin (validation des entrées)
- Détection d'altération via le tag GCM
- Validation stricte de toutes les entrées utilisateur

---

## Développeurs

Développé par Diego DELGADO et Léopold CASTEL-GAY

 

---



---

## Contexte du Projet



- Cryptographie appliquée (AES, PBKDF2)
- Développement d'interfaces graphiques (tkinter)
- Architecture logicielle modulaire
- Tests unitaires avec pytest
- Sécurité applicative selon les standards OWASP
- Documentation technique complète

---

## Support et Dépannage

### Problèmes courants

**"Module 'cryptography' not found"**
```bash
pip install cryptography
```

**"Can't open file 'main.py'"**
- Vérifier que vous êtes dans le dossier `guardiabox/`
- Utiliser `cd guardiabox` puis relancer

**"Tag d'authentification invalide"**
- Le fichier a été modifié ou corrompu
- Le mot de passe est incorrect
- Le fichier n'est pas un fichier chiffré valide

**Tests qui échouent**
```bash
pip install pytest pytest-cov
python -m pytest tests/ -v
```

---


