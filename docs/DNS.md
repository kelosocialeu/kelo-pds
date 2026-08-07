# DNS de Kelo PDS

## PDS

Le service PDS public est prévu sur :

```text
pds.kelosocial.eu
```

Ajoutez ce domaine comme Custom Domain sur Render puis créez le CNAME/A/ALIAS demandé par Render.

## Handles `nom.kelosocial.eu`

Le PDS est configuré avec :

```text
PDS_SERVICE_HANDLE_DOMAINS=.kelosocial.eu
```

Cela autorise la création de handles sous `kelosocial.eu`, indépendamment du hostname du PDS.

Cependant, un handle AT Protocol doit pouvoir être résolu vers le DID du compte. Il existe deux mécanismes standards :

1. DNS TXT `_atproto.<handle>` contenant `did=did:...`.
2. HTTPS sur `https://<handle>/.well-known/atproto-did` retournant le DID.

Pour des milliers de comptes, créer un TXT DNS individuel à chaque inscription est peu pratique. Une résolution HTTP wildcard est généralement plus simple : les sous-domaines `*.kelosocial.eu` doivent pouvoir atteindre un endpoint qui retourne le DID correspondant.

## Attention si `kelosocial.eu` héberge déjà l'application Kelo Social

Le domaine racine peut rester sur Vercel, mais le wildcard `*.kelosocial.eu` doit être pensé avec soin.

Options recommandées :

### Option A — faire gérer le wildcard par l'infrastructure Kelo Social

Le projet qui reçoit `*.kelosocial.eu` ne sert que `/.well-known/atproto-did` pour les sous-domaines de handles et laisse `kelosocial.eu` servir l'application normalement.

### Option B — Cloudflare devant les deux services

Utiliser Cloudflare pour router le domaine racine vers Kelo Social/Vercel et les requêtes wildcard nécessaires à la résolution AT Protocol vers le PDS ou un petit resolver.

### Option C — DNS TXT automatisé

À chaque création de compte, automatiser l'ajout de :

```text
_atproto.alice.kelosocial.eu TXT did=did:plc:...
```

Cette solution nécessite une API chez le fournisseur DNS et une gestion du cycle de vie des handles.

## Ne pas pointer aveuglément `*.kelosocial.eu` sur Render

Render sait fournir des certificats wildcard, mais sa configuration wildcard a des contraintes lorsque le domaine racine est servi ailleurs. Ne modifiez pas le domaine de production de Kelo Social avant d'avoir choisi le routage.

## Vérifications finales

Pour un compte `alice.kelosocial.eu`, ces opérations doivent fonctionner :

```text
resolveHandle(alice.kelosocial.eu) -> did:...
```

et le DID doit ensuite annoncer le PDS dans son document PLC.
