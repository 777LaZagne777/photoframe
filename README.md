# PhotoFrame

Cadre photo connecté pour Raspberry Pi. Les proches envoient leurs photos par Telegram ou par mail, ou on les ajoute depuis une page web. Elles s'affichent ensuite en diaporama plein écran sur l'écran branché au Pi.

Tout tient dans un seul script Python, [`photoframe.py`](photoframe.py), interface web comprise. Celle-ci ne charge aucune ressource externe.

## À quoi ça sert

- **Recevoir des photos par Telegram** : une personne s'enregistre auprès du bot avec un code d'accès, puis chaque photo qu'elle envoie arrive sur le cadre.
- **Recevoir des photos par mail** : le script relève une boîte Gmail dédiée et récupère les images jointes aux nouveaux messages.
- **Gérer le cadre depuis un navigateur** : ajout et suppression de photos, filtre par expéditeur, réglages, journaux, état du Pi (température, alimentation, réseau, disque).
- **Gérer le cadre depuis Telegram** : les gestionnaires consultent et suppriment les photos sans ouvrir le site.
- **Afficher les photos sans intervention** : chaque photo est préparée une fois à la taille de l'écran, et le diaporama `feh` redémarre tout seul s'il s'arrête.

### Cadrages disponibles

| Mode | Résultat |
|---|---|
| `mixte` | Recadre si moins de 20 % de l'image est coupée, sinon fond flou |
| `flou` | Photo entière sur un fond flou |
| `recadre` | Photo recadrée en plein écran |
| `bandes` | Photo entière avec des bandes noires |

### Commandes Telegram

| Commande | Pour qui | Effet |
|---|---|---|
| `/code MONCODE` | Tout le monde | S'enregistrer pour envoyer des photos |
| `/admin MONCODE` | Gestionnaires | S'inscrire avec un code à usage unique |
| `/photos` | Gestionnaires | Voir les 10 dernières photos, avec un bouton Supprimer |
| `/statut` | Gestionnaires | Voir l'état du cadre |
| `/diaporama` | Gestionnaires | Relancer l'affichage |
| `/ajouter`, `/retirer` | Gestionnaires | Donner ou retirer les droits de gestion |

## Installation

Testé sur Raspberry Pi 2 avec Raspbian 13 (trixie), Python 3.13, Flask 3.1 et Pillow 11.1. Cette procédure n'a pas été testée sur un Pi neuf. Les chemins supposent l'utilisateur `pi`.

```bash
sudo apt install python3-flask python3-pil python3-werkzeug feh x11-xserver-utils raspi-utils-core iproute2 caddy
mkdir -p ~/photoframe ~/photos
cp photoframe.py requirements.txt ~/photoframe/
cp .env.example ~/photoframe/.env
chmod 600 ~/photoframe/.env
```

Remplis ensuite `~/photoframe/.env` : chaque réglage y est commenté.

### Service systemd

Crée `/etc/systemd/system/photoframe.service` :

```ini
[Unit]
Description=PhotoFrame - cadre photo connecte
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=pi
WorkingDirectory=/home/pi/photoframe
EnvironmentFile=/home/pi/photoframe/.env
Environment=DISPLAY=:0
Environment=XAUTHORITY=/home/pi/.Xauthority
ExecStart=/usr/bin/python3 /home/pi/photoframe/photoframe.py
Restart=always
RestartSec=5

[Install]
WantedBy=graphical.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now photoframe
```

`feh` a besoin d'une session graphique ouverte sur l'écran du Pi, par exemple avec une connexion automatique.

Au premier démarrage, le mot de passe web généré s'affiche dans le journal :

```bash
journalctl -u photoframe | grep AUTH
```

### HTTPS avec Caddy

L'application n'écoute que sur `127.0.0.1` et son cookie de session exige HTTPS : sans proxy HTTPS, la connexion à l'interface ne tient pas. Exemple de `/etc/caddy/Caddyfile`, à adapter au nom de ton Pi :

```
mon-cadre.local {
	tls internal
	reverse_proxy localhost:8080
}
```

### Boutons de redémarrage

Les boutons de l'interface lancent `sudo -n systemctl restart photoframe` et `sudo -n reboot`. Pour qu'ils fonctionnent, ajoute une règle sudo qui autorise ces deux commandes sans mot de passe pour l'utilisateur du service.

## Sécurité

- **Secrets** : ils restent dans `.env`, exclu du dépôt par `.gitignore`, comme les listes de comptes Telegram et les photos.
- **Mot de passe web** : seul son hash est conservé.
- **Tentatives de connexion** : l'application ne les limite pas elle-même, malgré la mention « tentatives limitées » sur la page de connexion. Garde le cadre sur un réseau privé ou ajoute `fail2ban`, qui peut s'appuyer sur les lignes `[AUTH] login FAILED` du journal.
- **`WEB_AUTH=0`** : ce réglage supprime la page de connexion. Réserve-le à un réseau de confiance.

---

Signé **LaZagne**
