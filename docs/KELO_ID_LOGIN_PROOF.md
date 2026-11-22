# Connexion Kelo ID par preuve à usage unique

## Architecture

- **Kelo ID** authentifie l'utilisateur via sa session, puis appelle le PDS depuis son serveur.
- **Le PDS** fabrique, signe et vérifie la preuve.
- **Le Gatekeeper** ne fabrique et ne vérifie pas la preuve. Son correctif local dans `preauth_check` doit détecter `kelo-proof:v1:` et retourner `ProxyThrough`, en transmettant le mot de passe intact sans exiger le code de double authentification par e-mail.
- **AccountManager.login du PDS** valide le HMAC, l'expiration et le nonce à usage unique.

Le code du Gatekeeper est géré séparément sur la VM de l'administrateur. Ce dépôt ne le modifie ni ne le recrée.

## Contrat HTTP de l'émission

Composant : serveur PDS.

- Méthode : `POST`
- Chemin : `/kelo-id/login-proof`
- URL de production : `https://pds.kelosocial.eu/kelo-id/login-proof`
- En-têtes : `Authorization: Bearer <PDS_KELO_ID_API_KEY>` et `Content-Type: application/json`.
- Corps : `{"did":"did:plc:..."}` ou `{"did":"did:web:..."}`.
- Réponse 200 : `{"proof":"kelo-proof:v1:<expiration>:<nonce>:<signature>","expiresAt":<unix-seconds>}`.
- En-têtes de réponse : `Cache-Control: no-store, private` et `Pragma: no-cache`.

Codes :
- `400` : DID absent ou syntaxiquement invalide.
- `401` : clé Bearer invalide.
- `404` : DID non hébergé par ce PDS.
- `429` : plus de cinq demandes par DID dans une fenêtre de 60 secondes.
- `503` : service non configuré (clé API trop courte ou PDS_JWT_SECRET absent) ou erreur interne.

La clé API est `PDS_KELO_ID_API_KEY` sur le PDS et `KELO_PDS_API_KEY` sur le serveur Kelo ID. Ces deux valeurs doivent être identiques, aléatoires et d'au moins 32 caractères. Elles restent dans les variables d'environnement serveur ; elles ne sont jamais envoyées au navigateur.

## Format et dérivation cryptographique

Format conservé exactement :

`kelo-proof:v1:<expiration>:<nonce>:<signature>`

- expiration Unix en secondes ;
- nonce : 16 octets aléatoires cryptographiques, encodés en 32 caractères hexadécimaux minuscules ;
- signature : 32 octets HMAC-SHA256, encodés en 64 caractères hexadécimaux minuscules.

Texte signé exactement :

`v1|<DID>|<expiration>|<nonce>`

Dérivation historique exacte :

`derivedKey = HMAC-SHA256(key=PDS_JWT_SECRET, message="kelo-id-login-proof-v1")`

Le digest binaire de 32 octets devient la clé HMAC de la preuve :

`signature = HMAC-SHA256(key=derivedKey, message="v1|<DID>|<expiration>|<nonce>")`

La preuve est émise avec une expiration à `now + 60` secondes et le vérificateur refuse une preuve expirée ou dont l'expiration dépasse la fenêtre de 60 secondes. La comparaison des signatures utilise `timingSafeEqual`.

Aucune variable `PDS_KELO_ID_PROOF_SECRET` n'est créée ni utilisée. `PDS_JWT_SECRET` et la clé dérivée restent exclusivement dans le PDS. Kelo ID ne reçoit que la preuve signée et `expiresAt`.

## Usage unique

Après vérification du format, du DID, de l'expiration et du HMAC, le PDS crée atomiquement le fichier `/pds/kelo-id-proof-used/<nonce>`. L'ouverture en mode exclusif `wx` empêche deux connexions simultanées de consommer le même nonce. Les marqueurs sont conservés dix minutes avant nettoyage. Le disque persistant existant doit rester monté sur `/pds`. Ce mécanisme suppose une seule instance PDS utilisant ce volume.

## Passage par le Gatekeeper

Le patch PDS conserve le paramètre `password` et le transmet tel quel à `verifyKeloProof(user.did, password)`. Le test automatisé du patch vérifie cette transmission dans le code PDS.

Le Gatekeeper doit appliquer son propre correctif `preauth_check` sur la VM : préfixe `kelo-proof:v1:` → `ProxyThrough`, sans altérer le mot de passe et sans exiger la double authentification e-mail. Le dépôt GitHub ne contient pas ce code. Le test de bout en bout ne peut être considéré comme réussi qu'après le déploiement du correctif Gatekeeper par son administrateur. Un échec avant cette étape ne prouve pas que le HMAC du PDS est incorrect.

## Variables

PDS :
- `PDS_JWT_SECRET` : variable existante, ne pas la modifier ; utilisée aussi pour la dérivation.
- `PDS_KELO_ID_API_KEY` : nouvelle clé API partagée serveur-à-serveur.

Kelo ID :
- `KELO_PDS_URL=https://pds.kelosocial.eu`
- `KELO_PDS_API_KEY` : même valeur que `PDS_KELO_ID_API_KEY`.

Ne pas ajouter `PDS_KELO_ID_PROOF_SECRET`. Ne jamais transmettre `PDS_JWT_SECRET` ou la clé dérivée à Kelo ID.

## Tests

Les tests automatisés couvrent :
- format et longueur des champs ;
- dérivation HMAC historique depuis `PDS_JWT_SECRET` ;
- intégrité de signature et liaison au DID ;
- expiration et limite de 60 secondes ;
- usage unique et concurrence (une seule validation réussie) ;
- échec fermé si `PDS_JWT_SECRET` est absent ;
- idempotence des patches ;
- transmission inchangée du mot de passe au vérificateur PDS.

Après déploiement du Gatekeeper patché, faire un test de bout en bout avec un compte non-production : preuve fraîche, login client AT Protocol, rejeu refusé, puis mot de passe classique et mot de passe d'application. Ne pas tester avec les comptes réels.
