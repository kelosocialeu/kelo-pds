# Kelo PDS

Configuration du Personal Data Server AT Protocol de Kelo Social, conçue pour fonctionner sur Render à partir du PDS officiel.

## Objectifs

- Utiliser l'image officielle Bluesky/AT Protocol PDS et rester compatible avec les clients AT Protocol.
- Héberger le serveur sur `pds.kelosocial.eu` et permettre des handles `*.kelosocial.eu`.
- Conserver la configuration actuelle du CAPTCHA et du Gatekeeper.
- Accepter une preuve de connexion Kelo ID signée et vérifiée par le PDS, sans remplacer les mots de passe classiques ni les mots de passe d'application.
- Émettre les preuves par une API serveur-à-serveur authentifiée, avec une durée de 60 secondes et une protection anti-rejeu persistante.

## Déploiement

Render → Web Service → Docker, dépôt `kelosocialeu/kelo-pds`, branche `main`, Dockerfile `./Dockerfile`, healthcheck `/xrpc/_health`.

Guide : `docs/RENDER_WEB_SERVICE.md`.

Le Dockerfile reste épinglé à `ghcr.io/bluesky-social/pds:0.4.219`. Il conserve les modèles d'e-mails Kelo Social, le correctif OAuth `same-site` et les variables hCaptcha PDS vides déjà présentes. Le processus de démarrage upstream n'est pas remplacé.

## Connexion par Kelo ID

Le PDS expose `POST /kelo-id/login-proof`, réservé aux appels serveur-à-serveur de Kelo ID. Il vérifie que le DID est un compte de ce PDS, puis émet une preuve à usage unique.

Le Gatekeeper ne fabrique ni ne vérifie la preuve. Son correctif `preauth_check` séparé doit retourner `ProxyThrough` pour le préfixe `kelo-proof:v1:` et transmettre le mot de passe intact au PDS. La vérification HMAC, l'expiration et l'anti-rejeu sont effectués par le PDS dans `AccountManager.login`.

Format : `kelo-proof:v1:<expiration>:<nonce>:<signature>`.

- Texte signé : `v1|<DID>|<expiration>|<nonce>`.
- Clé dérivée dans le PDS : `HMAC-SHA256(PDS_JWT_SECRET, "kelo-id-login-proof-v1")`, digest binaire.
- HMAC de preuve : SHA-256, signature hex de 64 caractères.
- Expiration : 60 secondes.
- Nonce : 16 octets aléatoires, 32 caractères hex.
- Usage unique : création atomique d'un marqueur dans `/pds/kelo-id-proof-used`.

La clé dérivée et `PDS_JWT_SECRET` ne quittent jamais le PDS. Kelo ID ne reçoit que la preuve et son expiration. Aucune variable `PDS_KELO_ID_PROOF_SECRET` n'est utilisée.

Voir `docs/KELO_ID_LOGIN_PROOF.md` pour le contrat HTTP, les erreurs et les tests.

## Production

Conserver le disque persistant existant monté sur `/pds), sans le supprimer ni le réinitialiser. Le mécanisme anti-rejeu local suppose une seule instance PDS. Ne jamais régénérer `PDS_JWT_SECRET), la clé PLC, le mot de passe administrateur ou DPoP sur un PDS existant.

## CAPTCHA, OAuth et e-mails

Le Dockerfile conserve les variables hCaptcha PDS vides et le modèle d'environnement conserve `GATEKEEPER_CREATE_ACCOUNT_CAPTCHA=false`. Le correctif OAuth accepte `same-site`. Les cinq modèles d'e-mails (confirmation, réinitialisation, changement d'adresse, suppression et PLC) utilisent le logo Kelo Social `https://kelosocial.sirv.com/logo.png`.

## Santé et fédération

Le healthcheck est `/xrpc/_health`. Les connexions par mot de passe classique et mot de passe d'application restent inchangées.
