# Backend Shopix

## Configuration de l’administrateur

En production, configurez ces variables dans l’environnement du serveur (Render ou autre) :

- `ADMIN_USERNAME` : identifiant administrateur.
- `ADMIN_PASSWORD` : mot de passe administrateur fort.
- `JWT_SECRET` : secret aléatoire utilisé pour signer les sessions admin.
- `DATABASE_URL` : connexion PostgreSQL déjà requise en production.

Générez un secret avec `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"`. Ne partagez pas ces valeurs et ne les ajoutez pas au dépôt. Sans cette configuration, la connexion administrateur est désactivée en production. En développement local seulement, les identifiants par défaut sont `admin` / `admin123`.

Après connexion, la session admin expire au bout de 8 heures. Les listes de comptes et de commandes ainsi que leurs routes de suppression exigent ce jeton. Supprimer un compte conserve ses commandes ; supprimer une commande efface définitivement son enregistrement et ses articles.

## Paiement automatique MVola et API Android

Le site Shopix et l’application Android utilisent ce même backend Render et la même base PostgreSQL configurée dans `DATABASE_URL`. Les routes du Détecteur sont montées directement sur le serveur Shopix ; elles créent les tables d’association, de transactions et de notifications au démarrage sans toucher aux commandes existantes.

Le client effectue un transfert MVola au bénéficiaire affiché dans le panier et saisit la référence du reçu. L’APK transmet les SMS de réception reconnus directement à `/api/transactions`. La commande est validée automatiquement uniquement si la référence et le montant correspondent exactement. Une référence reconnue avec un montant incorrect, ou une référence incorrecte reliée sans ambiguïté au numéro du client, refuse la commande et crée une alerte visible dans l’administration. Une réception impossible à relier avec certitude crée une alerte sans refuser une commande au hasard.

Les colonnes de paiement et la table des alertes sont préparées automatiquement au démarrage ; les commandes existantes sont conservées. Une référence de transaction ne peut être associée qu’à une seule commande. Le tableau de bord admin actualise les alertes et les commandes toutes les 15 secondes.

### Configuration du webhook

L’API Android utilise la même URL que Shopix, par exemple `https://backend-shopix.onrender.com`. Le transfert est rapproché directement dans le backend : aucun second service Render ni secret de webhook partagé n’est requis. La route webhook authentifiée `/api/auth/device/mvola-transactions` reste disponible pour compatibilité avec d’anciens détecteurs.

## Lancer le backend localement

```sh
npm install
npm run dev
```

La création d’un compte client nécessite uniquement `phone` et `password`. Les nouveaux mots de passe sont hachés avec bcrypt ; les mots de passe historiques sont migrés vers bcrypt lors de leur prochaine connexion.
