# Sécurité et exploitation

## Secrets critiques

Ne jamais committer les valeurs suivantes :

- `PDS_JWT_SECRET`
- `PDS_ADMIN_PASSWORD`
- `PDS_DPOP_SECRET`
- `PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX`
- `PDS_HCAPTCHA_SECRET_KEY`
- `PDS_HCAPTCHA_TOKEN_SALT`
- identifiants SMTP
- identifiants S3 éventuels
- `PDS_KELO_ID_API_KEY`

Sauvegarder les secrets critiques hors de Render dans un gestionnaire de secrets sécurisé.

## Clé PLC

La clé `PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX` participe au contrôle des identités DID PLC créées par le PDS. Ne la remplacez pas arbitrairement une fois des comptes en production.

## Stockage

Le disque Render doit être monté sur `/pds`. Seuls les fichiers écrits sous ce chemin sont persistants.

Pour une charge importante, déplacer les blobs vers S3-compatible est préférable afin d'éviter de faire grossir le disque local avec toutes les photos et vidéos.

## Rate limiting

Conserver :

```text
PDS_RATE_LIMITS_ENABLED=true
```

Ne créez pas de bypass global public. Si le PDS est un jour exécuté avec plusieurs processus/instances, utilisez Redis/Valkey partagé pour le scratch/rate limiting.

## SSRF

Conserver :

```text
PDS_DISABLE_SSRF_PROTECTION=false
```

## Comptes et spam

La configuration actuelle conserve le CAPTCHA désactivé :
- les variables hCaptcha natives du PDS sont définies à des valeurs vides dans le Dockerfile ;
- `GATEKEEPER_CREATE_ACCOUNT_CAPTCHA=false) dans le modèle d'environnement.

Ne change pas ces paramètres pendant l'intégration Kelo ID. Conserver un e-mail fonctionnel, surveiller les créations anormales et les logs, et utiliser les mécanismes d'invitation existants si une attaque d'inscription le nécessite.

## Modération

Le PDS conserve les flux AT Protocol standard. En complément, il accepte une preuve Kelo ID signée et à usage unique comme méthode de connexion au compte PDS. L'émission est protégée par `PDS_KELO_ID_API_KEY`; la clé de signature est dérivée exclusivement depuis le `PDS_JWT_SECRET` existant avec le contexte `kelo-id-login-proof-v1`, selon la méthode historique. Aucune clé de signature indépendante n'est utilisée. Les preuves consommées sont marquées sur le volume persistant `/pds` afin que le redémarrage du conteneur ne réactive pas un code déjà utilisé.

Ne pas déployer plusieurs instances PDS avec des volumes locaux indépendants : l'anti-rejeu repose sur le volume persistant partagé par l'instance unique. Les mots de passe classiques et mots de passe d'application restent inchangés.

Le Gatekeeper est hors de ce dépôt. Son patch `preauth_check` doit transmettre intact au PDS les mots de passe commençant par `kelo-proof:v1:` via `ProxyThrough`. Ne pas considérer le test de bout en bout réussi avant son déploiement.

Les signalements AT Protocol sont envoyés au service de report configuré. Pour une modération Kelo indépendante à grande échelle, prévoir ensuite une infrastructure Ozone/labeler adaptée.

## Sauvegardes et restauration

Avant l'ouverture publique :

1. vérifier les snapshots Render ;
2. sauvegarder les secrets hors Render ;
3. documenter une restauration complète ;
4. tester la restauration sur un environnement non-production ;
5. surveiller la capacité disque.

## Mises à jour

Le Dockerfile est volontairement épinglé à une version précise. Pour mettre à jour :

1. lire les notes upstream ;
2. sauvegarder ;
3. modifier le tag du Dockerfile ;
4. déployer ;
5. vérifier `_health`, les sessions, uploads, WebSocket subscribeRepos et la visibilité via Relay/AppView.

Ne passez pas automatiquement à `latest` en production.
