# my_pgp

![Demo](docs/demo.gif)

Projet Epitech (G-CNA-500) : un outil en ligne de commande qui chiffre et déchiffre des
messages avec des algorithmes implémentés à la main, sans bibliothèque de cryptographie.

- **XOR** : chiffrement symétrique élémentaire ;
- **AES** : chiffrement symétrique par blocs standard (128, 192 et 256 bits) ;
- **RSA** : chiffrement asymétrique, avec génération de clés ;
- **PGP** (`pgp-xor`, `pgp-aes`) : chiffrement hybride. Le message est chiffré avec une clé
  symétrique, qui est elle-même chiffrée avec RSA ;
- **ElGamal** : second chiffrement asymétrique, fondé sur le logarithme discret ;
- **Diffie-Hellman** (`dh`) : échange de clés, puis chiffrement AES avec le secret commun.

En plus (« Going further » du sujet) : bourrages standards (`-p`), signatures (`-s`) et
génération de clés à partir de nombres premiers aléatoires (`-g -r`). Au-delà du sujet :
modes opératoires AES CBC et CTR (`-m`), authentification HMAC-SHA256 (`-a`) et clé PGP
aléatoire (`-k`). Le seul élément non codé à la main est la source d'aléatoire : le module
`secrets` de la bibliothèque standard (le générateur aléatoire cryptographique du système).

Le message est lu sur l'entrée standard, le résultat est écrit sur la sortie standard.

## Prérequis

- Python 3 (testé avec Python 3.12, aucune dépendance externe) ;
- `make`.

## Compilation

```sh
make          # construit l'exécutable ./my_pgp (archive zipapp Python)
make clean    # supprime les __pycache__
make fclean   # clean + supprime ./my_pgp
make re       # fclean + make
```

Sans compiler, le programme se lance aussi avec `python3 src ...`.

## Utilisation

```
./my_pgp CRYPTO_SYSTEM MODE [OPTIONS] [key]

CRYPTO_SYSTEM   xor | aes | rsa | pgp-xor | pgp-aes | elgamal | dh
MODE            -c        chiffrer le message lu sur l'entrée standard
                -d        déchiffrer le message lu sur l'entrée standard
                -g P Q    (rsa) générer une paire de clés à partir des premiers P et Q
                -g P X    (elgamal, dh) générer une paire de clés à partir du premier sûr P et de X
                -g -r [BITS]  (rsa, elgamal) générer une paire de clés aléatoire
                -g -r     (dh) clé aléatoire dans le groupe standard de 2048 bits
OPTIONS         -b        (xor, aes, pgp) un seul bloc : message et clé symétrique de même taille
                -p [oaep|pkcs1]  (xor, aes, rsa, pgp) bourrage standard, voir docs/padding.md
                -s        (rsa, pgp) signer / vérifier, voir docs/signature.md
                -m ecb|cbc|ctr   (aes, pgp-aes) mode opératoire, voir docs/modes.md
                -a        (xor, aes, pgp) tag HMAC-SHA256, voir docs/authentication.md
                -k        (pgp, avec -c) clé symétrique aléatoire, voir docs/pgp.md
```

`./my_pgp -h` affiche l'aide, **identique à celle du sujet** (les options en plus sont
décrites ici et dans `docs/`). Code de retour : `0` en cas de succès, `84` en cas d'erreur
(message `my_pgp: ...` sur la sortie d'erreur).

Les clés et les messages chiffrés sont en **hexadécimal little-endian** : voir
[docs/conventions.md](docs/conventions.md).

### Exemples (tirés du sujet)

```sh
# XOR (mode bloc : message et clé de même taille)
$ echo "You know nothing, Jon Snow" | ./my_pgp xor -c -b 576861742069732064656164206d6179206e6576657220646965
20070f2700071c6a4449060a490515164e4e12190b190011063c

# AES
$ echo "All men must die" | ./my_pgp aes -c -b 57696e74657220697320636f6d696e67
744ce22c385958348f0df26eceb62eef
$ echo "744ce22c385958348f0df26eceb62eef" | ./my_pgp aes -d -b 57696e74657220697320636f6d696e67
All men must die

# RSA : génération des clés puis chiffrement / déchiffrement
$ ./my_pgp rsa -g d3 e3
public key: 0101-19bb
private key: 9d5b-19bb
$ echo "WF" | ./my_pgp rsa -c 0101-19bb
8f84
$ echo "8f84" | ./my_pgp rsa -d 9d5b-19bb
WF

# PGP : 1re ligne = clé symétrique chiffrée en RSA, ensuite le message chiffré.
# Pour déchiffrer : clé = "clé chiffrée:clé privée", entrée = le message chiffré seul.
$ printf 'Hello' | ./my_pgp pgp-xor -c 6b65:0101-19bb
e802
0e2d07096b0a
$ echo 0e2d07096b0a | ./my_pgp pgp-xor -d e802:9d5b-19bb | cat -v
Hello^@
```

### Exemples des options en plus

```sh
# Clés RSA aléatoires (n de 2048 bits par défaut)
$ ./my_pgp rsa -g -r 1024

# Bourrage : le message revient exactement, sans les 00 de bourrage
$ printf 'Hello' | ./my_pgp xor -c -p 6b65
$ echo "WF" | ./my_pgp rsa -c -p pkcs1 <clé publique d'au moins 256 bits>

# Signature : la clé du signataire est ajoutée à la fin de la clé, la signature est sur la
# dernière ligne de la sortie et vérifiée avant de déchiffrer
$ echo "WF" | ./my_pgp rsa -c -s <publique destinataire>:<privée signataire> > out
$ ./my_pgp rsa -d -s <privée destinataire>:<publique signataire> < out
WF

# ElGamal : un fichier quelconque fait l'aller-retour à l'identique
$ ./my_pgp elgamal -g -r
public key: Y-G-P
private key: X-G-P
$ cat clear_file | ./my_pgp elgamal -c Y-G-P | ./my_pgp elgamal -d X-G-P > output
$ diff output clear_file && echo $?
0

# Modes opératoires : la 1re valeur de la sortie est l'IV (CBC) ou le compteur (CTR)
$ cat clear_file | ./my_pgp aes -c -m cbc -p 57696e74657220697320636f6d696e67
$ cat clear_file | ./my_pgp aes -c -m ctr 57696e74657220697320636f6d696e67

# Authentification : un tag HMAC suit le chiffré, vérifié avant de déchiffrer
$ printf 'pay 100 to Arya' | ./my_pgp aes -c -m ctr -a <clé> | ./my_pgp aes -d -m ctr -a <clé>
pay 100 to Arya

# PGP avec une clé symétrique aléatoire : seule la clé RSA est donnée
$ cat clear_file | ./my_pgp pgp-aes -c -k <publique destinataire> > out

# Diffie-Hellman : chacun génère sa paire, puis sa privée + la publique de l'autre
$ ./my_pgp dh -g -r
$ cat clear_file | ./my_pgp dh -c <privée Alice>:<publique Bob> | ./my_pgp dh -d <privée Bob>:<publique Alice>
```

## Tests

Les tests utilisent `unittest` (bibliothèque standard, rien à installer).

```sh
# Tous les tests, en lançant le programme via `python3 src`
python3 -m unittest discover -s tests -t .

# Avec le détail de chaque test
python3 -m unittest discover -s tests -t . -v

# Compile ./my_pgp puis lance les tests sur le binaire
make tests_run

# Un seul fichier / une seule classe / un seul test
python3 -m unittest tests.test_aes
python3 -m unittest tests.test_rsa.TestKeyGeneration
python3 -m unittest tests.test_xor.TestXorBlock.test_cipher_known_value
```

Les tests devraient aussi tourner avec `pytest tests` (non vérifié, pytest n'étant pas installé).

| Fichier                    | Contenu                                                              |
|----------------------------|----------------------------------------------------------------------|
| `tests/test_encoding.py`   | hexadécimal, little-endian, inversions d'octets                      |
| `tests/test_math_utils.py` | pgcd, ppcm, Euclide étendu, inverse et exponentiation modulaires     |
| `tests/test_aes_core.py`   | AES standard : GF(2^8), S-box, étapes de tour, vecteurs FIPS-197     |
| `tests/test_xor.py`        | XOR : modes bloc et flux, convention, erreurs                        |
| `tests/test_aes.py`        | AES avec la convention Epitech, modes bloc et flux, erreurs          |
| `tests/test_rsa.py`        | RSA : format des clés, génération, chiffrement, erreurs              |
| `tests/test_pgp.py`        | PGP : format des clés, format de sortie, allers-retours, cas limites (clé ≥ n, `00` final) |
| `tests/test_cli.py`        | analyse des arguments                                                |
| `tests/test_sha256.py`     | SHA-256 : constantes, bourrage, vecteurs FIPS, comparaison avec `hashlib` |
| `tests/test_padding.py`    | PKCS#7, OAEP, PKCS#1 v1.5, encodage de signature                     |
| `tests/test_padding_option.py` | option `-p` sur xor, aes, rsa et pgp                             |
| `tests/test_signature.py`  | option `-s` : signatures comparées à un oracle (`hashlib` + `pow`), falsifications |
| `tests/test_primes.py`     | Miller-Rabin (nombres de Carmichael...), premiers et premiers sûrs aléatoires |
| `tests/test_elgamal.py`    | ElGamal : génération, chiffrement vérifié avec `pow`, allers-retours exacts |
| `tests/test_modes.py`      | option `-m` : CBC et CTR (vecteurs NIST SP 800-38A), aes et pgp-aes |
| `tests/test_mac.py`        | HMAC-SHA256 (RFC 4231, module `hmac`), option `-a`, falsifications |
| `tests/test_random_key.py` | option `-k` : taille de la clé aléatoire, allers-retours via RSA |
| `tests/test_dh.py`         | Diffie-Hellman : groupe RFC 3526 recalculé, secret commun, clés invalides |
| `tests/test_functional.py` | bout en bout : codes de retour, stdout/stderr, pipes entre commandes |
| `tests/test_subject.py`    | tous les exemples du sujet, à l'octet près, et les premiers de l'annexe |
| `tests/helpers.py`         | oracles indépendants (vecteurs FIPS, `pow`, XOR, signature) et lancement du programme |

Les valeurs attendues viennent de sources indépendantes du code testé : vecteurs officiels
FIPS-197 (vérifiés avec `openssl`), calculs RSA faits avec `pow()` de Python, XOR recalculé
dans les tests.

**État actuel : 428 tests, tous verts**, y compris tous les exemples du sujet.

## Conformité au sujet (my_PGP v2.3)

| Partie                                         | État                                            |
|------------------------------------------------|-------------------------------------------------|
| `-h`, codes de retour 0 / 84, erreurs sur stderr | conforme                                      |
| XOR (bloc et flux)                             | conforme, exemple du sujet vérifié              |
| AES-128 (obligatoire), AES-192 / 256           | conforme, exemple du sujet vérifié              |
| RSA (`-g`, `-c`, `-d`, Fermat le plus grand, Carmichael) | conforme, exemples du sujet vérifiés  |
| pgp-aes                                        | conforme, exemple du sujet vérifié              |
| pgp-xor                                        | conforme (pas d'exemple dans le sujet)          |
| Second cryptosystème asymétrique (« should »)  | ElGamal, voir [docs/elgamal.md](docs/elgamal.md) |
| Signatures `-s` (« Going further »)            | rsa, pgp-xor, pgp-aes (RSA PKCS#1 v1.5 + SHA-256) |
| Générateur de premiers aléatoires              | `-g -r [BITS]` (Miller-Rabin), rsa et elgamal   |
| Schémas de bourrage                            | `-p` : PKCS#7, OAEP, PKCS#1 v1.5                |
| Rétrocompatibilité avec les exemples du sujet  | conforme : options en plus uniquement, `-h` inchangé |
| Modes opératoires (en plus du sujet)           | `-m cbc` / `-m ctr` sur aes et pgp-aes          |
| Authentification (en plus du sujet)            | `-a` : HMAC-SHA256, encrypt-then-MAC            |
| Clé PGP aléatoire (en plus du sujet)           | `-k` sur pgp-xor et pgp-aes                     |
| Échange de clés (en plus du sujet)             | `dh` : Diffie-Hellman + AES-256 CTR + HMAC      |

## Documentation

- [Conventions communes](docs/conventions.md) : hexadécimal, little-endian, modes bloc et flux, erreurs
- [XOR](docs/xor.md)
- [AES](docs/aes.md)
- [RSA](docs/rsa.md)
- [PGP](docs/pgp.md)
- [ElGamal](docs/elgamal.md)
- [Diffie-Hellman](docs/dh.md)
- [Bourrage (`-p`)](docs/padding.md)
- [Signatures (`-s`) et SHA-256](docs/signature.md)
- [Modes opératoires (`-m`)](docs/modes.md)
- [Authentification (`-a`)](docs/authentication.md)

## Structure du projet

```
src/
├── __main__.py        point d'entrée, aide, codes de retour
├── cli.py             analyse des arguments
├── dispatch.py        lecture de stdin, appel du bon système, écriture de stdout
├── encoding.py        hexadécimal, little-endian
├── math_utils.py      arithmétique modulaire
├── aes_core.py        AES standard (FIPS-197)
├── sha256.py          SHA-256 (FIPS 180-4)
├── padding.py         PKCS#7, OAEP, PKCS#1 v1.5, encodage des signatures
├── modes.py           modes opératoires CBC et CTR
├── mac.py             HMAC-SHA256, dérivation de clé
├── primes.py          Miller-Rabin, premiers et premiers sûrs aléatoires
├── errors.py          MyPgpError
└── systems/
    ├── base.py        classes de base : symétrique (blocs, bourrage, modes, tag) / asymétrique
    ├── xor.py
    ├── aes.py         convention Epitech autour de aes_core
    ├── rsa.py
    ├── pgp.py         pgp-xor, pgp-aes
    ├── elgamal.py
    └── dh.py          Diffie-Hellman
tests/                 tests unitaires et fonctionnels
docs/                  explications des algorithmes
```
