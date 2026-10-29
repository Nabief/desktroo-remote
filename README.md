# Desktroo Remote

Serveur d'assistance à distance auto-hébergé, installé depuis Desktroo Apps, les apps de [Desktroo](https://desktroo.fr).
Il fait tourner le serveur RustDesk officiel (hbbs, hbbr ; AGPL-3.0, non modifié) et le pilote depuis le bureau.

- **Serveur** : `server.js` lance et surveille `hbbs` (identifiants, ports 21115-21116) et `hbbr` (relais, port 21117),
  avec `-k _` (seuls les clients qui ont la clé du serveur sont acceptés). Clé et base des postes : `/data`.
  Les binaires viennent des versions officielles, vérifiés par empreinte SHA-256 dans le `Dockerfile`.
- **Adresse publique** : demandée à l'installation (`install_fields` → `RD_PUBLIC_HOST`), inscrite dans la configuration
  des postes et passée à hbbs comme relais.
- **Panneau** (port 8080) : derrière la session Desktroo ; refuse toute requête sans le secret posé par Desktroo.
  État, postes (nom, système, utilisateur, présence, notes), client Windows préconfiguré, script de déploiement, journal.
- **API des postes** (port 8081, ouvert par Desktroo sur le port 21114 du NAS) : un client RustDesk réglé sur ce serveur
  y envoie de lui-même sa présence (`/api/heartbeat`, toutes les 15 s) et sa fiche (`/api/sysinfo`). Un signal n'est
  retenu que si le poste est dans la base de hbbs avec le même identifiant matériel (uuid). Rien d'autre n'y est servi.
- **Techniciens** (port 8082, ouvert par Desktroo sur le port 21120 du NAS, **réseau local seulement**) : l'API complète
  que le client RustDesk utilise une fois connecté à un compte — `/api/login` (mot de passe haché scrypt, code TOTP
  facultatif sans réutilisation, 5 essais ratés par compte ou adresse → 15 min de blocage), `/api/currentUser`,
  `/api/logout`, `/api/peers`, `/api/users`, `/api/device-group/accessible` (onglet « Appareils accessibles » : tous les
  postes, rangés par groupe), `/api/ab` (carnet d'adresses personnel, format « ancien »). Depuis Internet, on y accède
  en HTTPS par un proxy (NPMplus) : le mot de passe ne circule jamais en clair. Le port public 21114 refuse ces routes.
  Jetons : `dtr_…`, gardés hachés (SHA-256), expirés après 90 jours sans usage, fermés au changement de mot de passe ou
  à la désactivation du compte. Comptes et jetons : `/data/auth.json` ; carnets : `/data/ab/` ; réglages :
  `/data/settings.json` (adresse de l'API des techniciens, langue des messages).
- **Client Windows préconfiguré** : le programme officiel de la dernière version, relayé depuis GitHub sous le nom
  `desktroo-remote--<config>.exe` (le client découpe le nom sur « -- » : le préfixe est ignoré) ; RustDesk lit sa configuration dans son nom (format de `custom_server.rs` :
  JSON `{host, key, api, relay}` en base64 « URL », renversé). Fonctionne quelle que soit la clé.
- **Habillage** (dans les scripts Windows) : sans toucher aux programmes signés, dépose `logo_light.png`,
  `logo_dark.png` (bandeau affiché par le client, `loadLogo`), `icon.png`/`icon.svg` (`loadIcon`) dans
  `RustDesk\data\flutter_assets\assets`, renomme les raccourcis « Desktroo Remote » avec `desktroo-remote.ico`.
  Une tâche planifiée SYSTEM (« Desktroo Remote - habillage », au démarrage puis toutes les heures) le réapplique après
  les mises à jour, et retire raccourcis, tâche et dossier une fois RustDesk désinstallé ; son dossier `C:\ProgramData\DesktrooRemote` n'est modifiable que par SYSTEM et les administrateurs.
  Images : `public/brand/`. Le nom « RustDesk » (titre, textes) reste : il est compilé dans la bibliothèque signée.
- **Script Windows** (`desktroo-remote.ps1`) : installe RustDesk comme service, vérifie la signature du programme,
  applique la configuration (`--config`), en option un mot de passe permanent aléatoire, et affiche l'ID.

Données : `/data/devices.json` (fiches, noms, notes), `/data/id_ed25519*` (clé du serveur : à sauvegarder),
`/data/db_v2.sqlite3` (base de hbbs).

## Publier une version

`powershell -ExecutionPolicy Bypass -File publish-app.ps1 remote 1.0.0 "première version"` depuis le dépôt Desktroo.
La fiche du catalogue est dans `tools\store\apps\remote.json` (canal `test` pour commencer).

## Mettre à jour le serveur RustDesk

Changer `RUSTDESK_SERVER_VERSION` et les deux empreintes `SHA256_*` dans le `Dockerfile`
(`sha256sum rustdesk-server-linux-amd64.zip rustdesk-server-linux-arm64v8.zip`), puis publier une version.

© 2026 Mdm-services.fr. Tous droits réservés. RustDesk Server : AGPL-3.0, voir `NOTICE`.
