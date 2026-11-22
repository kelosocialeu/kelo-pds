# Sécurité et exploitation

## Secrets critiques

Ne jamais committer ni afficher les valeurs réelles :
- `PDS_JWT_SECRET`
- `PDS_ADMIN_PASSWORD`
- `PDS_DPOP_SECRET`
- `PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX`
- `PDS_HCAPTCHA_SECRET_KEY`
- `PDS_HCAPTCHA_TOKEN_SALT`
- identifiants SMTP et S3
- `PDS_KELO_ID_API_KEY`

Les secrets restent dans le gestionnaire de secrets de l'hébergeur et sont masqués par `***` dans les comptes rendus.

## Identité et clé JWT

La clé `PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX` participe au contrôle des identités DID PLC. Ne la remplacez jamais arbitrairement après création des comptes. Ne régénérez pas non plus `PDS_JWT_SECRET` sur un PDS existant : elle sert à la session et à la dérivation historique de la clé Kelo ID.

Dérivation exacte : `HMAC-SHA256(key=PDS_JWT_SECRET, message="kelo-id-login-proof-v1")`, digest binaire de 32 octets. Aucune variable `PDS_KELO_ID_PROOF_SECRET` n'est utilisée.

## Stockage et anti-rejeu

Le disque Render existant reste monté sur `/pds`. Les marqueurs de preuve sont écrits uniquement dans `/pds/kelo-id-proof-used`. Ne supprimez pas ce répertoire pendant la fenêtre de rétention et ne réinitialisez jamais le volume de production.

La création exclusive des marqueurs empêche les validations simultanées. Cette stratégie suppose une seule instance PDS avec le même volume persistant.

## Rate limiting et SSRF

Conserver `PDS_RATE_LIMITS_ENABLED=true` et `PDS_DISABLE_SSRF_PROTECTION=false`. Ne créez pas de bypass global public.

## CAPTCHA, OAuth et e-mails

Ne changez pas la configuration CAPTCHA existante dans le cadre de cette intégration. Le Dockerfile conserve les variables hCaptcha PDS vides et `.env.example` conserve `GATEKEEPER_CREATE_ACCOUNT_CAPTCHA=false`. Le correctif OAuth `same-site` et les cinq modèles d'e-mails Kelo Social avec le logo officiel restent en place.

## Gatekeeper

Le Gatekeeper est hors de ce dépôt et de l'accès GitHub utilisé ici. Son correctif `preauth_check` est appliqué et déployé séparément par l'administrateur. Il doit transmettre sans modification les mots de passe commençant par `kelo-proof:v1:` au PDS. Ne pas prétendre qu'un test de bout en bout Gatekeeper a réussi tant que ce correctif n'est pas déployé.

## Sauvegardes et mises à jour

Avant tout déploiement, vérifier une sauvegarde récente du volume et conserver les secrets existants. Le Dockerfile reste épinglé à une version précise du PDS officiel. Toute mise à jour upstream exige de revalider les points d'ancrage et le build complet.
