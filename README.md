# Backend Shopix

## Configuration de l’administrateur

En production, configurez ces variables dans l’environnement du serveur (Render ou autre) :

- `ADMIN_USERNAME` : identifiant administrateur.
- `ADMIN_PASSWORD` : mot de passe administrateur fort.
- `JWT_SECRET` : secret aléatoire utilisé pour signer les sessions admin.
- `DATABASE_URL` : connexion PostgreSQL déjà requise en production.

Générez un secret avec `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"`. Ne partagez pas ces valeurs et ne les ajoutez pas au dépôt. Sans cette configuration, la connexion administrateur est désactivée en production. En développement local seulement, les identifiants par défaut sont `admin` / `admin123`.

Après connexion, la session admin expire au bout de 8 heures. Les listes de comptes et de commandes ainsi que leurs routes de suppression exigent ce jeton. Supprimer un compte conserve ses commandes ; supprimer une commande efface définitivement son enregistrement et ses articles.

## Paiement manuel MVola

Le client effectue lui-même un transfert MVola au bénéficiaire et au numéro affichés au panier, puis saisit la référence exacte figurant sur son reçu. La commande conserve séparément sa référence Shopix et cette référence de transaction. Elle reste « en attente » jusqu’à ce qu’un administrateur compare le reçu au transfert reçu et confirme manuellement le paiement dans le tableau de bord. La référence saisie seule ne prouve pas le paiement.

Les colonnes de paiement sont ajoutées automatiquement au démarrage ; les commandes existantes sont conservées. Une référence de transaction ne peut être associée qu’à une seule commande.

## Lancer le backend localement

```sh
npm install
npm run dev
```

La création d’un compte client nécessite uniquement `phone` et `password`. Les nouveaux mots de passe sont hachés avec bcrypt ; les mots de passe historiques sont migrés vers bcrypt lors de leur prochaine connexion.
