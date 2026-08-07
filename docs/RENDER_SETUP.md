# Déploiement Kelo PDS sur Render

Ce document décrit le déploiement initial. Ne créez aucun compte de production avant d'avoir validé le DNS, SMTP, hCaptcha, le disque persistant et la fédération.

## 1. Créer le Blueprint

Dans Render :

1. `New` → `Blueprint`.
2. Connecter le dépôt GitHub `kelosocialeu/kelo-pds`.
3. Choisir `render.yaml`.
4. Render créera le Web Service `kelo-pds` en région Frankfurt avec un disque de 20 Go monté sur `/pds`.

Le plan ne peut pas être Free car Render n'autorise les disques persistants que sur les services payants.

## 2. Secrets demandés pendant la création

### PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX

Générer **une seule fois** :

```bash
openssl ecparam --name secp256k1 --genkey --noout --outform DER | tail -c +8 | head -c 32 | xxd -p -c 32
```

Le résultat doit être une chaîne hexadécimale de 64 caractères. Sauvegardez-la hors de Render également.

### PDS_HCAPTCHA_SITE_KEY / PDS_HCAPTCHA_SECRET_KEY

Utiliser les valeurs de votre site hCaptcha autorisé pour les domaines de Kelo.

### PDS_EMAIL_SMTP_URL

Exemple Resend :

```text
smtps://resend:VOTRE_CLE_API@smtp.resend.com:465/
```

Si l'identifiant ou le mot de passe SMTP contient `@`, `:`, `/`, `&` ou d'autres caractères réservés, encoder ces caractères dans l'URL.

### PDS_EMAIL_FROM_ADDRESS

Exemple :

```text
Kelo Social <noreply@kelosocial.eu>
```

Le domaine d'envoi doit être autorisé par votre fournisseur SMTP.

## 3. Secrets générés automatiquement

Le Blueprint demande à Render de générer :

- `PDS_JWT_SECRET`
- `PDS_ADMIN_PASSWORD`
- `PDS_DPOP_SECRET`
- `PDS_HCAPTCHA_TOKEN_SALT`

Après création du service, faites une copie sécurisée de `PDS_ADMIN_PASSWORD` et des secrets d'identité dans votre gestionnaire de secrets.

## 4. Domaine public du PDS

Le Blueprint utilise actuellement :

```text
PDS_HOSTNAME=pds.kelosocial.eu
```

Dans Render → `kelo-pds` → `Settings` → `Custom Domains`, ajouter `pds.kelosocial.eu` puis suivre les valeurs DNS données par Render.

**Production importante :** les recommandations AT Protocol conseillent idéalement de séparer le domaine d'application du domaine PDS afin de réduire les risques liés au partage d'origine entre blobs/OAuth/application. Avant une très grosse ouverture publique, envisagez un domaine PDS dédié tout en conservant `.kelosocial.eu` comme domaine de handles via `PDS_SERVICE_HANDLE_DOMAINS`.

## 5. Domaine des handles

La configuration :

```text
PDS_SERVICE_HANDLE_DOMAINS=.kelosocial.eu
```

permet au PDS de proposer des handles comme :

```text
alice.kelosocial.eu
```

Le routage de `*.kelosocial.eu` pour la résolution d'identité doit être configuré séparément. Voir `docs/DNS.md` avant d'ouvrir les inscriptions.

## 6. Vérifier le service

Quand le déploiement est `Live`, ouvrir :

```text
https://pds.kelosocial.eu/xrpc/_health
```

Vous devez recevoir un JSON contenant une version.

Puis vérifier :

```text
https://pds.kelosocial.eu/xrpc/com.atproto.server.describeServer
```

Contrôler notamment :

- le DID du service ;
- les domaines de handles proposés ;
- les liens de politique ;
- la configuration d'inscription.

## 7. Tester la fédération

Après création d'un compte de test et d'un premier record, le PDS doit être vu par le Relay `bsky.network`. Les publications doivent ensuite remonter dans les services/AppViews compatibles.

Ne réinitialisez jamais un PDS de production sur le même hostname en supprimant ses bases : cela peut désynchroniser le Relay. Utilisez le processus de migration AT Protocol pour déplacer des comptes.

## 8. SMTP

Avant le lancement public :

- confirmer qu'un email de vérification arrive ;
- demander une réinitialisation de mot de passe ;
- vérifier l'expéditeur et SPF/DKIM/DMARC du domaine d'envoi.

## 9. hCaptcha

Tester une création de compte depuis un client compatible. Le PDS officiel possède les variables hCaptcha natives utilisées par ce dépôt.

Ne désactivez pas hCaptcha en production si `PDS_INVITE_REQUIRED=false`.

## 10. Sauvegardes

Render effectue des snapshots quotidiens des disques persistants, mais gardez également :

- une sauvegarde indépendante des secrets ;
- une procédure testée de restauration ;
- une surveillance de l'espace disque.

## 11. Montée en charge

Le PDS de référence utilise SQLite et ce Blueprint emploie un disque Render. Un disque Render est attaché à une seule instance : ce déploiement ne peut donc pas être simplement multiplié horizontalement.

Avant une charge importante :

- déplacer les blobs vers un stockage S3-compatible ;
- ajouter Render Key Value / Valkey pour `PDS_REDIS_SCRATCH_ADDRESS` si plusieurs processus doivent partager les limites ;
- surveiller CPU, RAM, latence et disque ;
- augmenter progressivement la taille d'instance ;
- tester la charge avant ouverture massive.
