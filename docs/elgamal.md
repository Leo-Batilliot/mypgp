# ElGamal

Code : [`src/systems/elgamal.py`](../src/systems/elgamal.py), [`src/primes.py`](../src/primes.py).

Le second cryptosystème asymétrique demandé par le sujet. Sa sécurité ne repose pas sur la
factorisation (RSA) mais sur le **logarithme discret** : connaissant `g`, `p` et
`y = g^x mod p`, retrouver `x` est infaisable pour un grand `p`.

## Clés

On part d'un **premier sûr** `p = 2q + 1` (avec `q` premier aussi).

1. `g` = le plus petit nombre `≥ 2` qui est un **carré** modulo `p`. Un carré vérifie
   `g^q mod p = 1` (critère d'Euler) ; son ordre divise donc `q`, qui est premier : il vaut
   `q`. `g` engendre ainsi le sous-groupe des carrés, de taille `q`, où le logarithme
   discret est difficile. (Quand `p ≡ ±1 mod 8`, 2 est un carré et `g = 2`.)
2. **Clé privée** : `x`, avec `1 ≤ x < q`.
3. **Clé publique** : `y = g^x mod p`.

Format (little-endian, comme RSA, le module en dernier) :

```
public key:  Y-G-P
private key: X-G-P
```

```sh
$ ./my_pgp elgamal -g 070001 d204       # p = 65543 (premier sûr), x = 1234
public key: c3e4-02-070001
private key: d204-02-070001
$ ./my_pgp elgamal -g -r                # p de 512 bits et x aléatoires
$ ./my_pgp elgamal -g -r 1024           # p de 1024 bits (~15 s : il faut que p et q soient premiers)
```

Comme pour RSA avec `-g P Q`, le programme suppose que `P` est un premier sûr sans le
vérifier (s'il n'en trouve pas de générateur, il s'arrête en erreur).

## Chiffrement

Pour chaque morceau `m` du message :

```
r  = nombre aléatoire, 1 ≤ r < q      (nouveau à chaque morceau)
c1 = g^r mod p
c2 = m × y^r mod p
```

`y^r = g^(xr)` est un **secret partagé** : l'expéditeur le calcule avec `y` et `r`, le
destinataire avec `c1` et `x`. C'est l'échange de clés de Diffie-Hellman, utilisé une seule
fois pour masquer `m`.

## Déchiffrement

```
s = c1^x mod p          (= g^(rx) = y^r)
m = c2 × s⁻¹ mod p      (inverse modulaire, Euclide étendu)
```

## Format et messages de toute longueur

Comme dans l'exemple X25519 du sujet, n'importe quel fichier est chiffré **tel quel** :
`cat fichier | ./my_pgp elgamal -c PUB | ./my_pgp elgamal -d PRIV` redonne exactement le
fichier, `\n` final compris (contrairement aux autres systèmes, il n'est pas retiré à la
lecture ni ajouté en sortie).

- le message est découpé en morceaux de `taille(p) - 2` octets ;
- on ajoute un octet `01` à la fin de chaque morceau avant d'en faire un nombre
  little-endian : les `00` de fin du morceau ne sont plus les octets de poids fort, ils ne
  sont donc pas perdus (le problème de RSA et de PGP sans `-p`) ; et le nombre reste `< p` ;
- chaque morceau donne une ligne `C1-C2`.

```sh
$ printf 'WF' | ./my_pgp elgamal -c c3e4-02-070001     # p de 3 octets : 1 octet par ligne, r aléatoire
59e0-665a
e13e-1392
```

Un déchiffrement avec la mauvaise clé donne presque toujours un morceau sans l'octet `01` :
erreur `invalid ciphered message (wrong key?)`.

## Comparaison avec RSA

|                     | RSA (sans `-p`)         | ElGamal                          |
|---------------------|-------------------------|----------------------------------|
| problème difficile  | factoriser `n`          | logarithme discret modulo `p`    |
| chiffré             | même taille que `n`     | **deux** nombres (2× plus gros)  |
| déterministe ?      | oui (même message → même chiffré) | **non** : `r` aléatoire |
| signature           | oui (`-s`)              | existe (DSA en dérive), non implémentée |

Le caractère aléatoire est la grande différence : ElGamal n'a pas besoin d'un bourrage
comme OAEP pour qu'Eve ne puisse pas tester des messages probables.

Limite de cette version « manuel » : `m` n'est pas forcé dans le sous-groupe des carrés, ce
qui laisse fuiter un bit d'information (si `m` est un carré ou non). Il est aussi malléable
(`c2 × 2` se déchiffre en `2m`). En pratique (OpenPGP), ElGamal sert à chiffrer une clé de
session, comme RSA dans `pgp-aes`.
