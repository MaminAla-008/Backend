# Backend Shopix

## Configuration de l’authentification

En production, configurez ces variables dans l’environnement du serveur (Render ou autre) :

- `ADMIN_USERNAME` : identifiant administrateur.
- `ADMIN_PASSWORD` : mot de passe administrateur fort.
- `JWT_SECRET` : secret aléatoire utilisé pour signer les sessions administrateur et client.
- `DATABASE_URL` : connexion PostgreSQL déjà requise en production.
- `GOOGLE_CLIENT_ID` : identifiant client OAuth Google, également utilisé au build du frontend comme `VITE_GOOGLE_CLIENT_ID`.
- `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN` et `TWILIO_VERIFY_SERVICE_SID` : identifiants serveur et Service SID Twilio Verify pour l’envoi et la validation des codes SMS.

Créez un client OAuth de type application Web dans Google Cloud; ajoutez les origines de votre frontend aux origines JavaScript autorisées, puis configurez le même client ID côté frontend et backend. Créez également un service Twilio Verify et configurez son SID et les identifiants Twilio uniquement sur le backend. Pour un compte Twilio d’essai, les numéros destinataires doivent généralement être vérifiés dans Twilio.

Générez `JWT_SECRET` avec `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"`. Ne partagez aucun secret et ne les ajoutez pas au dépôt. Sans `JWT_SECRET`, l’authentification est désactivée en production. En développement local seulement, les identifiants admin par défaut sont `admin` / `admin123`.

Après connexion, la session admin expire au bout de 8 heures et la session client au bout de 30 jours. Les routes de commandes client exigent le jeton du compte connecté et ne renvoient que ses commandes. Les listes de comptes et de commandes de l’administration ainsi que leurs routes de suppression exigent le jeton admin. Supprimer un compte conserve ses commandes ; supprimer une commande efface définitivement son enregistrement et ses articles.

La connexion Google vérifie le jeton d’identité auprès de Google et crée le compte Shopix à la première connexion. La réinitialisation envoie un code via Twilio Verify au numéro lié au compte; aucun mot de passe Google n’est lu ni récupéré.

## Paiement automatique MVola et API Android

Shopix et le Détecteur peuvent être déployés séparément. Le backend Shopix conserve les commandes dans sa base PostgreSQL `DATABASE_URL`. Le backend indépendant du Détecteur conserve les reçus dans sa propre base puis, si le webhook est configuré, transmet uniquement les réceptions reconnues par l’APK à Shopix.

Le client effectue un transfert MVola au bénéficiaire affiché dans le panier et saisit la référence du reçu. L’APK transmet les SMS de réception reconnus au backend Détecteur. La commande Shopix est validée automatiquement uniquement si la référence reçue est identique à la référence de commande et si le montant correspond exactement au total. Un montant incorrect sur une référence connue est refusé et crée une alerte visible dans l’administration. Une référence sans commande correspondante crée une alerte ; aucun rapprochement approximatif par numéro de téléphone ou date ne valide une commande.

Les colonnes de paiement et la table des alertes sont préparées automatiquement au démarrage ; les commandes existantes sont conservées. Une référence de transaction ne peut être associée qu’à une seule commande. Le tableau de bord admin actualise les alertes et les commandes toutes les 15 secondes.

### Configuration du webhook sécurisé

Configurez les variables d’environnement suivantes sur le backend Shopix et sur le backend Détecteur :

- `MVOLA_WEBHOOK_SECRET` : la même valeur aléatoire, au moins 32 caractères, sur les deux services.
- `SHOPIX_WEBHOOK_URL` (Détecteur uniquement) : URL complète `https://<BACKEND-SHOPIX>/api/auth/device/mvola-transactions`.

Générez le secret avec `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"`. Transmettez-le uniquement dans les variables secrètes de Render ; ne le placez ni dans l’APK, ni dans le frontend, ni dans un dépôt. La route Shopix vérifie le secret dans l’en-tête `X-MVola-Webhook-Secret`. En l’absence de ces variables côté Détecteur, les deux bases restent indépendantes et aucune commande n’est validée automatiquement.

## Lancer le backend localement

```sh
npm install
npm run dev
```

La création d’un compte client nécessite uniquement `phone` et `password`. Les nouveaux mots de passe sont hachés avec bcrypt ; les mots de passe historiques sont migrés vers bcrypt lors de leur prochaine connexion.
