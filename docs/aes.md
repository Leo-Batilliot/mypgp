# AES

Code : [`src/aes_core.py`](../src/aes_core.py) (algorithme standard) et
[`src/systems/aes.py`](../src/systems/aes.py) (convention Epitech).

## Principe

AES (Advanced Encryption Standard, FIPS-197) est un chiffrement **symétrique par blocs** :
il transforme un bloc de **16 octets** en un autre bloc de 16 octets à l'aide d'une clé de
**16, 24 ou 32 octets** (AES-128, AES-192, AES-256).

Le bloc est vu comme une matrice 4×4 d'octets (l'« état »), remplie colonne par colonne.

### Expansion de la clé

La clé est étendue en `Nr + 1` clés de tour de 16 octets (`Nr` = 10, 12 ou 14 tours selon la
taille de la clé). Chaque nouveau mot de 4 octets est le XOR du mot précédent et du mot situé
une clé plus tôt ; régulièrement, on lui applique une rotation (`RotWord`), une substitution
par la S-box (`SubWord`) et un XOR avec une constante de tour (`Rcon`).

### Chiffrement d'un bloc

```
AddRoundKey(clé 0)
répéter Nr - 1 fois :
    SubBytes      chaque octet remplacé via la S-box (non-linéarité)
    ShiftRows     la ligne i de la matrice est décalée de i cases vers la gauche
    MixColumns    chaque colonne est multipliée par une matrice fixe dans GF(2^8)
    AddRoundKey   XOR avec la clé du tour
dernier tour : SubBytes, ShiftRows, AddRoundKey (pas de MixColumns)
```

- **GF(2^8)** : les octets sont des polynômes ; l'addition est un XOR et la multiplication
  se fait modulo `x^8 + x^4 + x^3 + x + 1` (`0x11B`). Voir `xtime` et `gmul`.
- **Tables de multiplication** : MixColumns et InvMixColumns ne multiplient que par
  2, 3, 9, 11, 13 et 14. Les 256 résultats de chacune sont calculés au démarrage avec `gmul`
  (`MUL[c][x] == gmul(c, x)`), puis lus dans la table : même résultat, beaucoup plus rapide.
- **Table d'indices pour ShiftRows** : la permutation des 16 octets est toujours la même ;
  ses indices (`SHIFT_ROWS = (0, 5, 10, 15, 4, ...)`) sont calculés une fois au lieu d'être
  recalculés à chaque tour.

Avec ces deux tables, 1 Mo est chiffré en ~1,7 s (au lieu de ~15 s) et déchiffré en ~1,9 s
(au lieu de ~30 s), avec exactement les mêmes sorties.
- **S-box** : construite au démarrage : inverse dans GF(2^8) suivi d'une transformation
  affine. `SBOX[0x00] = 0x63`, `SBOX[0x53] = 0xED`.

### Déchiffrement

Les mêmes étapes en sens inverse avec les opérations inverses (`InvSubBytes`,
`InvShiftRows`, `InvMixColumns`) et les clés de tour dans l'ordre inverse.

## Convention Epitech

Le cœur (`AesCore`) est l'AES standard et passe les vecteurs officiels FIPS-197. Le projet
lit en plus chaque **mot de 4 octets en little-endian** :
- la clé donnée en argument a ses mots de 4 octets inversés avant d'être utilisée ;
- chaque mot de 4 octets du bloc chiffré est inversé avant affichage (et inversement au
  déchiffrement).

Exemple : la clé FIPS `000102030405060708090a0b0c0d0e0f` s'écrit
`03020100070605040b0a09080f0e0d0c` sur la ligne de commande.

```sh
$ echo 'All men must die' | ./my_pgp aes -c -b 03020100070605040b0a09080f0e0d0c
c6b6f042351a75eaf7447b6a72c91482
$ echo 'All men must die' | ./my_pgp aes -c -b 03020100070605040b0a09080f0e0d0c \
    | ./my_pgp aes -d -b 03020100070605040b0a09080f0e0d0c
All men must die
```

Exemple du sujet :

```sh
$ echo "All men must die" | ./my_pgp aes -c -b 57696e74657220697320636f6d696e67
744ce22c385958348f0df26eceb62eef
$ echo "744ce22c385958348f0df26eceb62eef" | ./my_pgp aes -d -b 57696e74657220697320636f6d696e67
All men must die
```

## Mode flux

Sans `-b`, le message est découpé en blocs de 16 octets (le dernier complété par des `00`)
chiffrés indépendamment (mode ECB). La sortie fait donc toujours un multiple de 32
caractères hexadécimaux. Au déchiffrement, un chiffré dont la taille n'est pas un multiple
de 16 octets voit son dernier morceau complété par des `00`, et le bourrage reste dans la
sortie (voir [conventions.md](conventions.md)).

## Erreurs gérées

- clé qui ne fait pas 16, 24 ou 32 octets, ou pas en hexadécimal ;
- en mode bloc : message ou chiffré qui ne fait pas 16 octets ;
- chiffré qui n'est pas de l'hexadécimal.
