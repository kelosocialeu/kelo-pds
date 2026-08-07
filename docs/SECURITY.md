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

Avec les inscriptions publiques :

- hCaptcha obligatoire ;
- email fonctionnel ;
- surveillance des créations anormales ;
- possibilité d'utiliser temporairement les invitations si une attaque d'inscription survient ;
- logs et métriques surveillés.

## Modération

Le PDS reste standard et n'impose pas Kelo ID. Les règles de vérification Kelo ID sont appliquées dans Kelo Social uniquement.

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
