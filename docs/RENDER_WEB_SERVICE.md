# Déploiement manuel sur Render — Web Service

## Service existant

Conserver le service existant : dépôt `kelosocialeu/kelo-pds`, branche `main`, runtime Docker, Dockerfile `./Dockerfile`, healthcheck `/xrpc/_health`, port `10000). Ne pas créer un second PDS.

## Protection des données

Avant toute opération de déploiement, vérifier que le disque persistant existant reste monté sur `/pds`. Ne jamais supprimer, réinitialiser, détacher ou remplacer ce disque. Ne pas modifier la base SQLite, les dépôts, les DID ou les blobs.

Les marqueurs anti-rejeu sont écrits uniquement dans `/pds/kelo-id-proof-used`. Le PDS doit rester en instance unique avec ce stockage local.

## Variables d'environnement

Conserver toutes les variables déjà configurées. Ne pas régénérer ni remplacer les secrets existants, notamment `PDS_JWT_SECRET`, la clé PLC, le mot de passe administrateur et DPoP.

Ajouter uniquement sur le PDS :
- `PDS_KELO_ID_API_KEY` : clé aléatoire partagée avec le serveur Kelo ID, au moins 32 caractères.

Sur le service Kelo ID :
- `KELO_PDS_URL=https://pds.kelosocial.eu`
- `KELO_PDS_API_KEY` : même valeur que `PDS_KELO_ID_API_KEY`.

La clé de signature est dérivée dans le PDS depuis le `PDS_JWT_SECRET` existant. Ne pas définir `PDS_KELO_ID_PROOF_SECRET`. Masquer toute valeur réelle par `***`.

## CAPTCHA, OAuth et e-mails

Le Dockerfile conserve les variables hCaptcha natives du PDS vides et le modèle `.env.example` conserve `GATEKEEPER_CREATE_ACCOUNT_CAPTCHA=false`. Il conserve aussi le correctif OAuth acceptant `same-site` et les cinq modèles d'e-mails Kelo Social avec le logo `https://kelosocial.sirv.com/logo.png`. Ne change pas ces éléments.

## API et vérifications

L'API d'émission est `POST https://pds.kelosocial.eu/kelo-id/login-proof`, protégée par `Authorization: Bearer <PDS_KELO_ID_API_KEY>`, avec le corps JSON `{"did":"did:..."}`. La réponse 200 contient `proof` et `expiresAt`. Voir `docs/KELO_ID_LOGIN_PROOF.md` pour le contrat complet.

Après un déploiement contrôlé, vérifier le healthcheck, le DID well-known, les connexions par mot de passe et mot de passe d'application, l'émission, la première utilisation et le refus du rejeu. Le test de bout en bout Gatekeeper ne se fait qu'après déploiement du correctif `preauth_check` par son administrateur. Ce dépôt ne déploie ni ne modifie le Gatekeeper.
