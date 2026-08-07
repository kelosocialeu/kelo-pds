# Déploiement manuel sur Render — Web Service

Ce guide permet de déployer `kelo-pds` sans Blueprint, directement comme **Web Service Docker**.

## 1. Créer le service

Dans Render :

1. `New` → `Web Service`
2. Connecter le dépôt `kelosocialeu/kelo-pds`
3. Branch : `main`
4. Runtime / Language : `Docker`
5. Dockerfile path : `./Dockerfile`
6. Health Check Path : `/xrpc/_health`
7. Auto Deploy : activé sur `main`

Le conteneur écoute sur le port `10000`. Ajouter `PDS_PORT=10000` dans les variables Render.

## 2. Important : stockage

Le PDS utilise SQLite et des blobs locaux par défaut. Sans disque persistant Render, `/pds` est **éphémère** : un redéploiement, une reconstruction ou certains redémarrages peuvent supprimer comptes, dépôts et médias.

- Pour un **test temporaire** : le Web Service sans disque peut démarrer, mais ne créez pas de vrais comptes importants.
- Pour la **production** : attacher un disque persistant monté sur `/pds`, ou migrer vers une architecture de stockage durable compatible avec le PDS.

Ne lancez jamais publiquement un PDS contenant de vrais utilisateurs en considérant le filesystem gratuit comme une sauvegarde.

## 3. Variables d'environnement minimales

### Service

```text
PDS_PORT=10000
PDS_HOSTNAME=pds.kelosocial.eu
PDS_SERVICE_NAME=Kelo Social PDS
PDS_SERVICE_HANDLE_DOMAINS=.kelosocial.eu
PDS_HOME_URL=https://kelosocial.eu
PDS_LOGO_URL=https://kelosocial.sirv.com/logo.png
PDS_CONTACT_EMAIL_ADDRESS=support@kelosocial.eu
PDS_PRIVACY_POLICY_URL=https://kelosocial.eu/privacy
PDS_TERMS_OF_SERVICE_URL=https://kelosocial.eu/terms
```

### Secrets permanents

```text
PDS_JWT_SECRET=<64 caractères hex aléatoires ou plus>
PDS_ADMIN_PASSWORD=<secret fort>
PDS_DPOP_SECRET=<64 caractères hex aléatoires ou plus>
PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX=<clé secp256k1 privée hex>
```

Ne changez jamais la clé PLC d'un PDS existant sans procédure de rotation/migration : elle fait partie des secrets critiques de l'identité du serveur.

### Stockage local

```text
PDS_DATA_DIRECTORY=/pds
PDS_BLOBSTORE_DISK_LOCATION=/pds/blocks
PDS_BLOBSTORE_DISK_TMP_LOCATION=/pds/tmp
PDS_BLOB_UPLOAD_LIMIT=104857600
```

### Réseau AT Protocol public

```text
PDS_DID_PLC_URL=https://plc.directory
PDS_BSKY_APP_VIEW_URL=https://api.bsky.app
PDS_BSKY_APP_VIEW_DID=did:web:api.bsky.app
PDS_REPORT_SERVICE_URL=https://mod.bsky.app
PDS_REPORT_SERVICE_DID=did:plc:ar7c4by46qjdydhdevvrndac
PDS_CRAWLERS=https://bsky.network
```

### Inscription et hCaptcha

```text
PDS_INVITE_REQUIRED=false
PDS_HCAPTCHA_SITE_KEY=<site key hCaptcha>
PDS_HCAPTCHA_SECRET_KEY=<secret hCaptcha>
PDS_HCAPTCHA_TOKEN_SALT=<secret aléatoire>
```

### Email

```text
PDS_EMAIL_SMTP_URL=<URL SMTP>
PDS_EMAIL_FROM_ADDRESS=Kelo Social <noreply@kelosocial.eu>
```

### Sécurité

```text
PDS_RATE_LIMITS_ENABLED=true
PDS_DISABLE_SSRF_PROTECTION=false
LOG_ENABLED=true
LOG_LEVEL=info
```

## 4. Domaine Render puis domaine Kelo

Le premier déploiement peut être testé sur le domaine `*.onrender.com` fourni par Render, mais le PDS de production doit ensuite utiliser `pds.kelosocial.eu` de façon stable.

Dans Render → Settings → Custom Domains, ajouter :

```text
pds.kelosocial.eu
```

Puis suivre la cible DNS CNAME fournie par Render chez le registrar DNS.

Le `PDS_HOSTNAME` doit rester `pds.kelosocial.eu`; ne le remplacez pas par le domaine temporaire `onrender.com` pour le PDS définitif.

## 5. Vérifications après déploiement

Tester :

```text
https://pds.kelosocial.eu/xrpc/_health
https://pds.kelosocial.eu/.well-known/atproto-did
```

Le healthcheck doit répondre correctement. Ensuite seulement, tester la création d'un compte temporaire.

## 6. Âge

Le PDS reste un PDS AT Protocol standard. La collecte/confirmation d'âge de Kelo doit être gérée dans le parcours d'inscription Kelo. Nous n'ajoutons pas de champ propriétaire à `com.atproto.server.createAccount`, afin de conserver la compatibilité avec les clients AT Protocol.

## 7. Vérification Kelo ID

Aucun blocage Kelo ID n'est implémenté dans le PDS. Un compte `*.kelosocial.eu` reste utilisable normalement depuis les autres clients AT Protocol. Les restrictions de publication avant vérification restent uniquement dans l'application Kelo Social.
