# Connexion OAuth Kelo PDS avec Kelo ID

## Parcours utilisateur

1. Une application AT Protocol redirige l'utilisateur vers le point d'autorisation OAuth de Kelo PDS.
2. Si le navigateur ne possède pas encore de session Kelo PDS, la page présente un QR Kelo ID et conserve une option de connexion classique.
3. L'utilisateur scanne le QR avec l'application Kelo ID existante.
4. Kelo ID vérifie que la session est authentifiée, puis affiche le nom du client OAuth, son identifiant complet et les autorisations demandées.
5. L'utilisateur doit appuyer explicitement sur **Autoriser** ou **Refuser**.
6. En cas d'autorisation, le PDS associe le DID à l'appareil du navigateur qui a lancé OAuth. Le navigateur reprend ensuite la demande OAuth d'origine et le fournisseur AT Protocol termine le parcours normal (consentement et retour vers l'application cliente).

La connexion identifiant/mot de passe existante reste disponible. Le bouton classique conduit à l'écran de connexion natif du PDS. Si le navigateur possède déjà une session, l'interface OAuth native continue de s'afficher normalement.

## Sécurité

- Le QR contient uniquement un jeton aléatoire de 256 bits, sans mot de passe, JWT ni secret.
- Le jeton expire après cinq minutes.
- La demande est liée au request_uri, au client_id et à l'identifiant de l'appareil OAuth créé par le PDS.
- Le PDS valide à nouveau la demande PAR et le login_hint avant d'associer le compte.
- L'approbation passe par une API serveur-à-serveur protégée par la clé Kelo ID existante.
- Le PDS enregistre l'approbation avant que le navigateur puisse reprendre OAuth.
- Le jeton ne peut pas autoriser une autre demande ni un autre appareil.
- Les demandes sont stockées sous le volume persistant /pds/kelo-id-oauth-challenges.

## Variables existantes

Aucune nouvelle variable ni aucun nouveau secret n'est requis.

- Oracle / Kelo PDS : PDS_KELO_ID_API_KEY
- Application Kelo ID : KELO_PDS_API_KEY — exactement la même valeur
- Application Kelo ID : KELO_PDS_URL=https://pds.kelosocial.eu

Ne pas modifier PDS_JWT_SECRET, les clés PLC, les clés DPoP ou les secrets de session existants.

## Périmètre

- Cette méthode ne concerne que les comptes hébergés sur pds.kelosocial.eu.
- Les utilisateurs d'un autre PDS continuent de s'authentifier auprès de leur propre PDS.
- Le QR de preuve humaine / certification de Kelo Social reste indépendant et inchangé.
- Le QR de liaison et de connexion rapide Kelo Social reste inchangé.
- Kelo ID utilise son application web mobile existante et ses permissions caméra ; aucune application native supplémentaire n'est créée.

## Déploiement

Le commit GitHub ne déploie pas le conteneur Oracle à lui seul. Après validation de la construction Docker, reconstruire et redémarrer le conteneur Kelo PDS en conservant le volume existant /opt/kelo-pds:/pds et le fichier d'environnement actuel. Ne pas recréer le volume et ne pas modifier les secrets.

Le déploiement de Kelo ID doit également être déclenché sur son hébergement habituel afin de publier la nouvelle route serveur et la mise à jour du scanner.
