# Kelo PDS

Configuration du Personal Data Server AT Protocol de Kelo Social, conçue pour fonctionner sur Render à partir du PDS officiel.

## Objectifs

- Utiliser l'image officielle Bluesky/AT Protocol PDS.
- Rester compatible avec Bluesky et les autres clients AT Protocol.
- Héberger le serveur sur `pds.kelosocial.eu`.
- Permettre des handles comme `nom.kelosocial.eu`.
- Utiliser le hCaptcha natif du PDS pour la création de comptes.
- Garder la vérification Kelo ID uniquement dans Kelo Social, jamais dans le PDS.
- Activer SMTP, fédération, rate limiting, protection SSRF, healthcheck et logs.

## Méthode de déploiement recommandée actuellement

Le déploiement recommandé est maintenant **Render → Web Service → Docker**.

Le fichier `render.yaml` reste disponible pour un éventuel Blueprint plus tard, mais il n'est pas nécessaire pour le déploiement manuel.

Guide exact :

```text
docs/RENDER_WEB_SERVICE.md
```

## Configuration Render Web Service

- Repository : `kelosocialeu/kelo-pds`
- Branch : `main`
- Runtime : `Docker`
- Dockerfile : `./Dockerfile`
- Health check : `/xrpc/_health`
- Port PDS : `10000`

Le `Dockerfile` utilise directement l'image officielle du PDS :

```text
ghcr.io/bluesky-social/pds:0.4.219
```

Aucun script de démarrage Kelo propriétaire n'est nécessaire : on conserve le comportement upstream du PDS.

## Important : stockage Render

Le PDS écrit ses données sous `/pds`.

Pour un simple test, un Web Service sans disque persistant peut démarrer, mais le filesystem Render est éphémère. Les comptes, dépôts et médias peuvent disparaître lors d'une reconstruction ou d'un redéploiement.

**Ne pas considérer un Web Service sans disque comme une installation de production.**

Pour de vrais utilisateurs, il faudra un stockage durable avant l'ouverture publique.

## Âge / Age Assurance

AT Protocol ne prévoit pas de date de naissance dans `com.atproto.server.createAccount`. Bluesky applique son système d'Age Assurance au niveau produit/AppView.

Kelo pourra donc demander l'âge ou la date de naissance dans son propre parcours d'inscription avant d'appeler l'API standard du PDS, sans ajouter de champ propriétaire au protocole.

## hCaptcha

Le PDS utilise ses variables natives :

```text
PDS_HCAPTCHA_SITE_KEY
PDS_HCAPTCHA_SECRET_KEY
PDS_HCAPTCHA_TOKEN_SALT
```

Cela évite d'inventer un proxy d'inscription incompatible avec AT Protocol.

## Fédération

Configuration réseau publique prévue :

```text
PDS_DID_PLC_URL=https://plc.directory
PDS_BSKY_APP_VIEW_URL=https://api.bsky.app
PDS_BSKY_APP_VIEW_DID=did:web:api.bsky.app
PDS_CRAWLERS=https://bsky.network
PDS_REPORT_SERVICE_URL=https://mod.bsky.app
PDS_REPORT_SERVICE_DID=did:plc:ar7c4by46qjdydhdevvrndac
```

## Fichiers

- `Dockerfile` — image officielle PDS épinglée.
- `.env.example` — liste des variables à entrer dans Render.
- `render.yaml` — Blueprint optionnel, non requis pour Web Service manuel.
- `docs/RENDER_WEB_SERVICE.md` — déploiement manuel Render.
- `docs/RENDER_SETUP.md` — ancien parcours Blueprint / référence complémentaire.
- `docs/DNS.md` — DNS du PDS et des handles.
- `docs/SECURITY.md` — secrets, sauvegardes et production.
- `docs/AGE_AND_CAPTCHA.md` — âge et hCaptcha.

## Secrets critiques

Une fois de vrais comptes créés, sauvegarder de façon sécurisée :

```text
PDS_JWT_SECRET
PDS_ADMIN_PASSWORD
PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX
PDS_DPOP_SECRET
```

En particulier, ne pas remplacer arbitrairement la clé PLC après création des identités.

## Healthcheck

Render doit utiliser :

```text
/xrpc/_health
```

Le PDS doit être considéré comme prêt uniquement lorsque ce point de contrôle répond correctement.
