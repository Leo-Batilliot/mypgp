# Bourrage (`-p`)

Code : [`src/padding.py`](../src/padding.py)

Sans `-p`, le programme fait exactement ce que demande le sujet : bourrage par des `00`
pour XOR / AES, RSA « brut » (`c = m^e mod n`). Avec `-p`, il utilise les bourrages
standards. Les exemples du sujet ne sont pas modifiés.

```sh
./my_pgp xor|aes CHIFFRER_OU_DECHIFFRER -p KEY            # PKCS#7
./my_pgp rsa     -c|-d -p [oaep|pkcs1] KEY                # OAEP par défaut
./my_pgp pgp-xor|pgp-aes -c|-d -p [oaep|pkcs1] KEY        # les deux
```

`-p` doit être donné **au chiffrement et au déchiffrement**, avec le même schéma.

## Pourquoi le bourrage du sujet ne suffit pas

- **Symétrique** : avec des `00`, on ne sait pas au déchiffrement si les `00` de la fin
  faisaient partie du message. C'est pour ça que `xor` / `aes` sans `-p` rendent le message
  suivi de ses `00`.
- **RSA brut** est **déterministe** : le même message donne toujours le même chiffré. Eve
  peut donc tester des messages probables (« oui », « non », une clé AES courte...) en les
  chiffrant avec la clé publique et en comparant. Il est aussi **malléable** :
  `c × 2^e` se déchiffre en `2m`, sans connaître la clé privée. Et un petit `m` avec un petit
  `e` donne `m^e < n` : la racine e-ième entière suffit à retrouver `m`.

## PKCS#7 (XOR, AES)

On ajoute `k` octets valant `k`, avec `1 ≤ k ≤ taille du bloc` : **toujours au moins un
octet**, même si le message tombe juste (on ajoute alors un bloc entier).

```
"abc"  bloc de 4  →  61 62 63 01
"ab"   bloc de 4  →  61 62 02 02
"abcd" bloc de 4  →  61 62 63 64 04 04 04 04
```

Au déchiffrement, le dernier octet dit combien d'octets retirer ; on vérifie qu'ils ont tous
cette valeur, sinon erreur. Le message revient **exactement** (les `00` de fin compris).

- Pas de `-p` avec `-b` : un bloc unique fait déjà exactement la taille de la clé.
- XOR : la clé (= le bloc) doit faire au plus 255 octets, puisque `k` tient sur un octet.

## RSA : principe commun

Le message est d'abord transformé en un bloc `EM` de **la taille de `n`** (`k` octets), qui
commence par `00`. `EM` est lu comme un nombre **big-endian**, comme dans le standard
PKCS#1 : son premier octet `00` est alors l'octet de poids fort, ce qui garantit `EM < n`. Le
chiffré `EM^e mod n`, lui, est affiché en little-endian comme tous les nombres du programme.

Les deux schémas ajoutent de l'**aléatoire** : chiffrer deux fois le même message donne deux
chiffrés différents, ce qui casse l'attaque « je teste des messages probables ».

### PKCS#1 v1.5 (`-p pkcs1`)

```
EM = 00 || 02 || PS || 00 || message        PS = au moins 8 octets aléatoires non nuls
```

Il faut `message ≤ k - 11` octets : avec les premiers de 256 bits de l'annexe (`n` de 64
octets), jusqu'à 53 octets, assez pour une clé AES.

Faiblesse connue : **l'attaque de Bleichenbacher (1998)**. Si le destinataire révèle d'une
façon ou d'une autre si le bourrage d'un chiffré est valide (message d'erreur différent,
temps de réponse...), Eve peut, avec des millions de chiffrés modifiés, retrouver le message.
C'est pour ça que le programme renvoie toujours la même erreur (`invalid padding`).

### OAEP (`-p` ou `-p oaep`)

Le standard moderne (PKCS#1 v2, RFC 8017), avec SHA-256 :

```
DB         = SHA-256("") || 00 ... 00 || 01 || message
seed       = 32 octets aléatoires
maskedDB   = DB   XOR MGF1(seed, taille de DB)
maskedSeed = seed XOR MGF1(maskedDB, 32)
EM         = 00 || maskedSeed || maskedDB
```

`MGF1(x, L)` = `SHA-256(x || 00000000) || SHA-256(x || 00000001) || ...` coupé à `L`
octets : un générateur de masque de n'importe quelle longueur.

Les deux « tours » de masquage (comme un mini-réseau de Feistel) font que chaque bit d'`EM`
dépend de tout le message et de tout le seed : modifier le chiffré donne un `EM` dont la
structure (`SHA-256("")`, puis `00...01`) a très peu de chances d'être valide. OAEP est
prouvé sûr contre les attaques à chiffrés choisis (dans le modèle de l'oracle aléatoire).

Il faut `message ≤ k - 66` octets : **les premiers de 256 bits ne suffisent pas** (`n` = 64
octets), il faut au moins ceux de 1024 bits de l'annexe ou `rsa -g -r`.

## PGP

Avec `-p`, la clé symétrique est chiffrée en RSA avec le schéma choisi, **comme une suite
d'octets** : elle revient intacte au déchiffrement (plus de perte des `00` de fin, plus de
problème de clé `≥ n`, voir [pgp.md](pgp.md)). Le message est bourré en PKCS#7 en mode flux,
et pas bourré en mode bloc.

```sh
$ echo "All men must die" | ./my_pgp pgp-aes -c -p pkcs1 57696e74657220697320636f6d696e67:010001-c9f9...2fb3
<clé AES chiffrée, différente à chaque fois>
<message chiffré, 2 blocs>
$ <message chiffré> | ./my_pgp pgp-aes -d -p pkcs1 <clé AES chiffrée>:81b0...2fb3
All men must die
```
