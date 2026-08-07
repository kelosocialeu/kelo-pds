# Âge et hCaptcha

## hCaptcha

Le PDS officiel expose désormais les variables natives :

```text
PDS_HCAPTCHA_SITE_KEY
PDS_HCAPTCHA_SECRET_KEY
PDS_HCAPTCHA_TOKEN_SALT
```

Kelo PDS les active avec les clés fournies dans Render. Avec les inscriptions ouvertes (`PDS_INVITE_REQUIRED=false`), hCaptcha constitue la protection principale contre les créations automatisées de comptes.

Les secrets hCaptcha restent exclusivement dans Render. Seule la site key est destinée à être exposée au navigateur lorsqu'un client affiche le challenge.

## Âge : ne pas casser AT Protocol

Le endpoint standard `com.atproto.server.createAccount` ne possède pas de champ universel de date de naissance à stocker dans le PDS.

L'Age Assurance utilisée par Bluesky est une politique de l'application/AppView Bluesky. Un utilisateur Kelo peut donc se connecter au même compte depuis Bluesky et suivre les règles d'âge imposées par Bluesky pour sa juridiction.

Kelo ne doit pas ajouter arbitrairement `birthDate` au record de création PDS et considérer ce champ comme une extension obligatoire : cela rendrait les clients tiers incompatibles.

## Parcours recommandé pour Kelo Social

Dans l'interface d'inscription Kelo :

1. Demander la date de naissance / déclaration d'âge selon la politique Kelo applicable.
2. Faire accepter les CGU et la politique de confidentialité.
3. Faire le hCaptcha.
4. Valider les règles Kelo côté serveur.
5. Appeler ensuite le endpoint AT Protocol standard de création du compte.

La règle d'âge Kelo reste une règle produit Kelo Social. Elle n'empêche pas le compte AT Protocol d'être utilisé par un autre client qui applique sa propre politique.

## Données minimales

Éviter de copier inutilement une date de naissance dans le dépôt AT Protocol public. Si Kelo doit conserver une information réglementaire, stocker le strict minimum dans le système privé prévu pour la conformité, avec durée de conservation définie et accès restreint.
