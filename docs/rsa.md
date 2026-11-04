# RSA

Code : [`src/systems/rsa.py`](../src/systems/rsa.py) et [`src/math_utils.py`](../src/math_utils.py).

## Principe

RSA est un chiffrement **asymétrique** : une **clé publique** sert à chiffrer, une **clé
privée** différente sert à déchiffrer. Sa sécurité repose sur la difficulté de factoriser un
grand nombre `n = p × q` quand on ne connaît pas les premiers `p` et `q`.

### Génération des clés (`-g P Q`)

1. `n = p × q` (le module, partagé par les deux clés) ;
2. `λ(n) = ppcm(p - 1, q - 1)` (indicatrice de Carmichael) ;
3. `e` = le **plus grand** nombre premier de Fermat (`65537, 257, 17, 5, 3`) tel que
   `1 < e < λ(n)` et `pgcd(e, λ(n)) = 1`, comme l'impose le sujet ;
4. `d = e⁻¹ mod λ(n)` (inverse modulaire, calculé par l'algorithme d'Euclide étendu).

Clé publique : `(e, n)`. Clé privée : `(d, n)`.

### Chiffrement / déchiffrement

Le message est converti en un entier `m` (little-endian). Pour pouvoir être retrouvé, il doit
être **strictement inférieur à `n`** ; un message plus grand est quand même chiffré, mais le
déchiffrement donne `m mod n` :

```
chiffré  c = m^e mod n
déchiffré m = c^d mod n
```

Ça marche parce que `e × d ≡ 1 (mod λ(n))`, donc `m^(e×d) ≡ m (mod n)`. Les puissances sont
calculées par exponentiation rapide (`modexp`).

## Format des clés

Une clé s'écrit `EXPOSANT-MODULE`, chacun en hexadécimal little-endian. `P` et `Q` sont aussi
donnés en hexadécimal little-endian.

Exemple du sujet :

```sh
$ ./my_pgp rsa -g d3 e3          # p = 211, q = 227
public key: 0101-19bb            # e = 257, n = 47897
private key: 9d5b-19bb
$ echo "WF" | ./my_pgp rsa -c 0101-19bb
8f84
$ echo "8f84" | ./my_pgp rsa -d 9d5b-19bb
WF
```

Ici `65537` n'est pas retenu car il est plus grand que `λ(n) = 23730` : on passe à `257`.

> Comme le sujet l'autorise, le programme ne vérifie pas que `P` et `Q` sont premiers : avec
> des nombres non premiers, les clés générées ne permettent pas de retrouver le message.

## Clés aléatoires (`-g -r [BITS]`)

Code : [`src/primes.py`](../src/primes.py).

```sh
$ ./my_pgp rsa -g -r          # n de 2048 bits (deux premiers de 1024 bits), ~1 s
$ ./my_pgp rsa -g -r 512      # n de 512 bits
```

`BITS` est la taille de `n`, en décimal (c'est une taille, pas une donnée). Le reste de la
génération (`e`, Carmichael, `d`, format de sortie) est identique à `-g P Q`.

Générateur de premiers :

1. tirer un nombre impair de la bonne taille avec `secrets` (le générateur aléatoire
   cryptographique du système ; `random` est prévisible et ne doit jamais servir à ça) ;
   les **deux** bits de poids fort sont mis à 1, pour que `p × q` ait exactement `BITS` bits ;
2. l'éliminer s'il est divisible par un des premiers `< 2000` (élimine ~85 % des candidats impairs
   pour presque rien) ;
3. test de **Miller-Rabin** : on écrit `n - 1 = d × 2^s` avec `d` impair. Si `n` est premier,
   pour toute base `a`, soit `a^d ≡ 1`, soit `a^(d·2^r) ≡ -1 (mod n)` pour un `r < s`. Une base
   qui ne vérifie pas ça **prouve** que `n` est composé. Un composé passe au plus 1/4 des
   bases : après 40 bases aléatoires, la probabilité d'erreur est `≤ 4^-40`.

Contrairement au test de Fermat (`a^(n-1) ≡ 1`), Miller-Rabin n'est pas trompé par les
nombres de Carmichael (561, 1105, ...).

On recommence si `p = q` ou si aucun premier de Fermat n'est premier avec `λ(n)`.

## Bourrage et signature

- `-p [oaep|pkcs1]` : bourrage OAEP ou PKCS#1 v1.5, voir [padding.md](padding.md) ;
- `-s` : signature du chiffré, voir [signature.md](signature.md).

## Particularités

- Un seul `\n` final sur l'entrée est ignoré ; le déchiffrement ajoute un `\n`.
- L'option `-b` n'a pas d'effet sur RSA.
- Les octets `00` en fin de message sont perdus (ils ne changent pas la valeur de l'entier).
- Une partie vide dans une clé vaut 0 (`-19bb` : exposant 0) ; un module 1 donne toujours
  `00`.
- Un chiffré vide vaut 0 : `rsa -d` affiche alors l'octet `00` suivi de `\n`.
- `-g` avec `P = Q` génère des clés (λ = P − 1), qui ne permettent pas de retrouver le
  message.

## Erreurs gérées

- `-g` avec autre chose que `rsa` ou `elgamal`, `P`/`Q` manquants, pas en hexadécimal ou `< 2` ;
- `-g -r` avec moins de 16 bits ;
- aucun exposant valide (ex. `-g 02 03`) ;
- clé qui n'a pas la forme `E-N` ;
- module 0 (au moment du calcul).
