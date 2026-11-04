# PGP (pgp-xor, pgp-aes)

Code : [`src/systems/pgp.py`](../src/systems/pgp.py)

## Principe : le chiffrement hybride

RSA est sûr mais lent et limité à des messages plus petits que `n`. Les chiffrements
symétriques (XOR, AES) sont rapides mais demandent de partager la clé secrète. PGP combine
les deux :

1. le message est chiffré avec une **clé symétrique** (XOR ou AES) ;
2. cette clé symétrique, courte, est chiffrée avec la **clé publique RSA** du destinataire ;
3. le destinataire déchiffre la clé symétrique avec sa **clé privée RSA**, puis le message.

## Protocole (conforme au sujet)

**Chiffrement** : clé `CLE_SYMETRIQUE:CLE_RSA_PUBLIQUE`. La sortie contient :
- ligne 1 : la clé symétrique chiffrée en RSA (la clé est lue comme un nombre little-endian) ;
- ensuite : le message chiffré avec la clé symétrique (même format que `xor` / `aes`).

**Déchiffrement** : clé `CLE_SYMETRIQUE_CHIFFREE:CLE_RSA_PRIVEE`, et sur l'entrée standard
**uniquement** le message chiffré (sans la première ligne).

Exemple du sujet :

```sh
$ echo "All men must die" | ./my_pgp pgp-aes -c -b 57696e74657220697320636f6d696e67:010001-c9f9...2fb3
97f2af4c1b712008c1e46935f446756443a8a700f20581d138e4e6916afe5c5f9b9d6eaa0a870374b686f1a024f9bbb88c23c766654579339caf55afd149d41d
744ce22c385958348f0df26eceb62eef
$ echo "744ce22c385958348f0df26eceb62eef" | ./my_pgp pgp-aes -d -b 97f2...d41d:81b0...e209-c9f9...2fb3
All men must die
```

Petit exemple avec les clés RSA de `-g d3 e3` :

```sh
$ printf 'Hello' | ./my_pgp pgp-xor -c 6b65:0101-19bb
e802
0e2d07096b0a
$ echo 0e2d07096b0a | ./my_pgp pgp-xor -d e802:9d5b-19bb | cat -v
Hello^@
```

(le `00` de bourrage revient au déchiffrement, comme pour `xor`).

La clé est vérifiée **avant** de lire l'entrée standard : en `-c` elle doit être une clé
valide pour le système symétrique, en `-d` un nombre hexadécimal quelconque (éventuellement
vide, ce qui vaut 0).

## Clé récupérée par RSA

Au déchiffrement, la clé symétrique est utilisée **exactement telle que RSA la rend**, sous
sa forme minimale. Elle peut donc différer de la clé d'origine :

- **clé plus grande que `n`** : elle est chiffrée en `k^e mod n` sans erreur, et le
  déchiffrement retrouve `k mod n`. Avec les premiers de 256 bits du sujet, `n` fait 64
  octets ; avec `-g d3 e3`, seulement 2 octets ;
- **clé qui se termine par `00`** (ex. `6b6500`) : c'est le même nombre que `6b65`, la clé
  revient donc plus courte.

Conséquences :

- **pgp-xor, mode flux** : le chiffré est découpé en blocs de la taille de la clé récupérée,
  le dernier complété par des `00`, et déchiffré sans erreur (la sortie ne redonne alors pas
  le message d'origine) ;
- **pgp-xor, mode bloc** : le chiffré doit avoir la taille de la clé récupérée, sinon erreur ;
- **pgp-aes** : si la clé récupérée ne fait pas 16, 24 ou 32 octets, erreur.

Avec `-p`, ces deux problèmes disparaissent : la clé est chiffrée comme une suite d'octets
bourrée (OAEP ou PKCS#1 v1.5) et revient intacte. Voir [padding.md](padding.md).

## Clé symétrique aléatoire (`-k`)

Dans le vrai PGP, la clé symétrique n'est pas choisie par l'utilisateur : elle est tirée au
hasard pour chaque message. Avec `-k` (au chiffrement seulement), la clé ne contient plus que
la partie RSA, et la sortie a le format habituel :

```sh
$ printf 'All men must die' | ./my_pgp pgp-aes -c -k 010001-c9f9...2fb3 > out
$ tail -n +2 out | ./my_pgp pgp-aes -d "$(head -1 out):81b0...e209-c9f9...2fb3"
```

- **pgp-aes** : la plus longue clé AES que RSA peut transporter (32, sinon 24, sinon 16 octets).
- **pgp-xor** : une clé **aussi longue que le message** quand RSA le permet : c'est alors un vrai
  masque jetable (one-time pad). Sinon, aussi longue que RSA le permet. En mode bloc, elle
  fait la taille du message, ou erreur.
- RSA transporte au plus `taille de n − 1` octets sans `-p` (tout nombre plus court que `n` est
  plus petit que `n`), `taille de n − 66` avec OAEP et `taille de n − 11` avec PKCS#1 v1.5.
- Le dernier octet de la clé (l'octet de poids fort du nombre chiffré par RSA) n'est jamais
  `00` : la clé revient de RSA avec sa longueur, même sans `-p`.

## Options en plus du sujet

- `-p [oaep|pkcs1]` : clé symétrique bourrée avant RSA, message bourré en PKCS#7 en mode
  flux ([padding.md](padding.md)) ;
- `-s` : la clé devient `SYM:RSA:RSA_SIGNATAIRE`, et la sortie se termine par une ligne de
  signature qui couvre la clé chiffrée et le message chiffré ([signature.md](signature.md)) ;
- `-m cbc|ctr` (pgp-aes) : mode opératoire d'AES pour le message ([modes.md](modes.md)) ;
- `-a` : tag HMAC sur le message chiffré ([authentication.md](authentication.md)) ;
- `-k` : clé symétrique aléatoire (ci-dessus).
