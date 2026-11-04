# Modes opératoires (`-m`)

Code : [`src/modes.py`](../src/modes.py), [`src/systems/base.py`](../src/systems/base.py)

AES ne chiffre qu'un bloc de 16 octets. Le **mode opératoire** dit comment enchaîner les blocs
d'un message plus long. Sans `-m` (ou avec `-m ecb`), le programme fait le mode flux du sujet.

```sh
./my_pgp aes     -c|-d -m ecb|cbc|ctr [-p] KEY
./my_pgp pgp-aes -c|-d -m ecb|cbc|ctr [-p [oaep|pkcs1]] SYM:RSA_KEY
```

`-m` doit être donné **au chiffrement et au déchiffrement**, avec le même mode. Il ne se
combine pas avec `-b` (un seul bloc, rien à enchaîner).

## ECB : le mode flux du sujet

Chaque bloc est chiffré seul : `C[i] = AES(P[i])`. AES étant déterministe, **deux blocs
identiques donnent le même chiffré**, et la structure du message reste visible :

```sh
$ printf 'Winter is comingWinter is comingHodor hodor hodor!' | ./my_pgp aes -c 57696e74657220697320636f6d696e67 | fold -w 32
332449dbf70ae8f736c8ee38ed9922e2      <- "Winter is coming"
332449dbf70ae8f736c8ee38ed9922e2      <- "Winter is coming" : même chiffré
cce7d2cf1411f87310a87152a9681b6e
fb8b3d60d7fa888644ab8743fab20d69
```

Eve ne lit pas le message, mais elle voit ce qui se répète, et peut recopier, retirer ou
réordonner des blocs (sur une image : le « pingouin ECB »).

## CBC (`-m cbc`)

Chaque bloc est XORé avec le **chiffré précédent** avant d'être chiffré ; le premier avec un
**IV** (vecteur d'initialisation) de 16 octets aléatoires :

```
C[0] = IV
C[i] = AES(P[i] ⊕ C[i-1])          déchiffrement : P[i] = AES⁻¹(C[i]) ⊕ C[i-1]
```

- **Sortie** : `IV || C[1] || C[2] ...` sur une seule ligne hexadécimale. L'IV n'est pas
  secret, mais le destinataire en a besoin ; il est nouveau à chaque chiffrement.
- Deux blocs identiques ne donnent plus le même chiffré, et chiffrer deux fois le même
  message donne deux sorties différentes (chiffrement **probabiliste**).
- Le message est bourré comme sans `-m` : des `00` (qui reviennent au déchiffrement), ou
  PKCS#7 avec `-p`.
- Au déchiffrement, il faut l'IV puis un nombre entier de blocs, sinon erreur.

```sh
$ printf 'Winter is comingWinter is comingHodor hodor hodor!' | ./my_pgp aes -c -m cbc 57696e74657220697320636f6d696e67 | fold -w 32
e29c696561aa21a911957a1d1b02b65e      <- IV (change à chaque fois)
ea15d1e686123319bfc1136c9024b223
6af21fe9f18047950455af934d8167c1      <- plus de répétition
b48f6f7bcde3edc0e8f865e417229390
fe15679045284f9c50f42c8a81ba3079
```

## CTR (`-m ctr`)

AES ne chiffre **pas le message** mais un **compteur** ; le résultat sert de clé XOR, aussi
longue que le message :

```
flux = AES(N) || AES(N+1) || AES(N+2) ...      (N : 16 octets aléatoires, lus en big-endian)
C    = P ⊕ flux                                 déchiffrement : P = C ⊕ flux, la même opération
```

- **Sortie** : `N || C`, où `C` a exactement la taille du message : **rien n'est bourré**,
  le flux est coupé à la taille du message. `-p` est donc refusé avec `aes -m ctr` (avec
  `pgp-aes`, `-p` continue de bourrer la clé RSA).
- Seul le chiffrement AES sert, même pour déchiffrer.
- C'est le XOR du sujet, avec la seule chose qui lui manquait pour être sûr : une clé aussi
  longue que le message, fabriquée à partir d'une clé courte.
- **Règle d'or** : ne jamais réutiliser `N` avec la même clé. Deux messages chiffrés avec le
  même flux donnent `C1 ⊕ C2 = P1 ⊕ P2`, l'attaque du XOR à clé réutilisée.

```sh
$ printf 'Winter is comingWinter is comingHodor hodor hodor!' | ./my_pgp aes -c -m ctr 57696e74657220697320636f6d696e67 | fold -w 32
27cd603c85ca33f28974651a0f04d2d7      <- N (change à chaque fois)
4954cf7c4dd7335c3d07658035613127
39b08aeda1b260a155e53ba0bdf97f37
f08b2faf9bf11ff8fd3590d10285926e
84ab                                   <- 50 octets de message, 50 octets de chiffré
```

## Ce qu'aucun des deux ne protège : l'intégrité

CBC et CTR cachent le message, mais ne l'empêchent pas d'être modifié. En CTR, inverser un
bit du chiffré inverse le même bit du message : `pay 100 to Arya` devient `pay 900 to Arya`
sans connaître la clé (testé dans `tests/test_modes.py`). C'est le rôle de `-a`
([authentication.md](authentication.md)).

## Convention Epitech

Les modes s'appliquent au bloc AES **du programme**, celui de `aes -b` (clé et blocs chiffrés
avec les mots de 32 bits inversés, voir [aes.md](aes.md)) :

- en CBC, les blocs enchaînés sont les blocs affichés ; avec un IV nul, le premier bloc est
  donc exactement celui d'ECB ;
- en CTR, chaque bloc du flux est ce qu'affiche `aes -c -b` pour le compteur.

`src/modes.py` ne dépend d'aucune convention : il prend la fonction qui chiffre un bloc. Il est
vérifié avec l'AES standard sur les vecteurs officiels **NIST SP 800-38A** (F.2.1 pour CBC,
F.5.1 pour CTR), recoupés avec `openssl`.

## Comparatif

|                                    | ECB (défaut)  | CBC                     | CTR                    |
|------------------------------------|---------------|-------------------------|------------------------|
| Blocs identiques → chiffrés identiques | oui       | non                     | non                    |
| Même message → même sortie         | oui           | non (IV)                | non (compteur)         |
| Bourrage                           | `00` ou PKCS#7 | `00` ou PKCS#7         | aucun                  |
| Utilise AES⁻¹                      | oui           | oui                     | non                    |
| Parallélisable                     | oui           | déchiffrement seulement | oui                    |
| Point critique                     | —             | IV imprévisible         | compteur jamais réutilisé |
