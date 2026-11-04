# XOR

Code : [`src/systems/xor.py`](../src/systems/xor.py)

## Principe

Le XOR (ou exclusif) bit à bit a une propriété clé : `(m ^ k) ^ k = m`. On chiffre en
combinant chaque octet du message avec l'octet correspondant de la clé, et on déchiffre en
refaisant exactement la même opération.

```
message   0110 0001   ('a')
clé     ^ 0111 1001   (0x79)
        = 0001 1000   (0x18)   -> chiffré
clé     ^ 0111 1001
        = 0110 0001   ('a')    -> retrouvé
```

C'est un chiffrement **symétrique** : la même clé sert à chiffrer et à déchiffrer. Utilisé
avec une clé aléatoire aussi longue que le message et jamais réutilisée, c'est le « masque
jetable », incassable. Avec une clé courte répétée, il est en revanche très facile à casser.

## Convention little-endian

La clé et le bloc sont lus comme des nombres little-endian. En pratique, pour un bloc :

```
chiffré = inverse(message) XOR clé
```

Exemple avec la clé `6b6579` (« key ») et le message `abc` :

```
inverse("abc") = 63 62 61
clé            = 6b 65 79
XOR            = 08 07 18   -> "080718"
```

```sh
$ printf 'abc' | ./my_pgp xor -c -b 6b6579
080718
$ echo 080718 | ./my_pgp xor -d -b 6b6579
abc
```

Exemple du sujet (une clé aussi longue que le message) :

```sh
$ echo "You know nothing, Jon Snow" | ./my_pgp xor -c -b 576861742069732064656164206d6179206e6576657220646965
20070f2700071c6a4449060a490515164e4e12190b190011063c
$ echo 20070f2700071c6a4449060a490515164e4e12190b190011063c | ./my_pgp xor -d -b 576861742069732064656164206d6179206e6576657220646965
You know nothing, Jon Snow
```

## Mode flux

Sans `-b`, le message est découpé en blocs de la taille de la clé (le dernier complété par
des `00`), et chaque bloc est chiffré comme ci-dessus.

```sh
$ echo 'I love spinach' | ./my_pgp xor -c 6b6579
0745300e13161b16590a0b106b0d1a
$ echo 'I love spinach' | ./my_pgp xor -c 6b6579 | ./my_pgp xor -d 6b6579 | cat -v
I love spinach^@
```

Le `\n` d'`echo` n'est pas chiffré ; le `00` de bourrage (`^@`) revient au déchiffrement,
suivi d'un `\n`.

## Erreurs gérées

- clé absente, vide ou pas en hexadécimal ;
- en mode bloc : message ou chiffré de taille différente de la clé ;
- chiffré qui n'est pas de l'hexadécimal.
