# Diffie-Hellman (`dh`)

Code : [`src/systems/dh.py`](../src/systems/dh.py)

Un **échange de clés** : Alice et Bob obtiennent un secret commun sans jamais l'envoyer, puis
chiffrent avec. C'est le principe sur lequel repose ElGamal ([elgamal.md](elgamal.md)), et
celui de l'exemple X25519 du sujet.

## Principe

Alice et Bob partagent un groupe public : un premier sûr `p` et un générateur `g`.

```
Alice : x_A secret, Y_A = g^x_A mod p public        Bob : x_B secret, Y_B = g^x_B mod p public

Alice calcule  S = Y_B^x_A = g^(x_B x_A)
Bob   calcule  S = Y_A^x_B = g^(x_A x_B)             →  le même S
```

Eve voit `g`, `p`, `Y_A` et `Y_B`. Retrouver `S` lui demanderait de résoudre le problème de
Diffie-Hellman, aussi difficile en pratique que le logarithme discret.

## Utilisation

```sh
$ ./my_pgp dh -g -r            # Alice (puis Bob, de son côté)
public key: Y_A-02-P
private key: X_A-02-P
$ cat clear_file | ./my_pgp dh -c X_A-02-P:Y_B-02-P > ciphered       # Alice : sa privée, la publique de Bob
$ ./my_pgp dh -d X_B-02-P:Y_A-02-P < ciphered > output               # Bob : sa privée, la publique d'Alice
$ diff output clear_file && echo $?
0
```

Clé = `MA_CLE_PRIVEE:SA_CLE_PUBLIQUE`. N'importe quel fichier revient à l'identique, retour à la
ligne final compris (comme `elgamal`).

## Clés

Même format et même calcul que les clés ElGamal (`Y-G-P` et `X-G-P`, little-endian).

- `dh -g -r` : une clé privée aléatoire dans le **groupe standard** de la RFC 3526 (groupe 14,
  `p` de 2048 bits, `g = 2`). Les deux côtés doivent être dans le **même groupe** : avec un
  premier aléatoire chacun, leurs clés seraient inutilisables ensemble. C'est pour ça que les
  vrais protocoles utilisent des groupes publiés. `dh -g -r` ne prend donc pas de taille.
- `dh -g P X` : une clé dans un autre groupe ; les deux côtés doivent alors utiliser le même `P`.

Le premier de la RFC 3526 vaut `2^2048 − 2^1984 − 1 + 2^64 × (⌊2^1918 π⌋ + 124476)` (π sert
de nombre « sans rien dans la manche »). Les tests le recalculent à partir de π et vérifient
que c'est un premier sûr.

## Chiffrement

1. `S = Y^x mod p` (le secret partagé) ;
2. clé AES-256 = `SHA-256(S)` (`S` en little-endian, sur autant d'octets que `p`) : on ne
   chiffre pas directement avec `S`, dont les bits ne sont pas uniformes ;
3. le message est chiffré exactement comme par `aes -c -m ctr -a` avec cette clé : sortie =
   une ligne hexadécimale `compteur || chiffré || tag` ([modes.md](modes.md),
   [authentication.md](authentication.md)).

Les deux clés étant fixes, Alice et Bob ont **toujours le même secret** : c'est le compteur
aléatoire qui rend chaque chiffrement différent, et le tag qui détecte toute modification ou
mauvaise clé.

## Vérifications

- les deux clés ont le même `g` et le même `p` ;
- la clé privée vérifie `1 ≤ x < q` (`q = (p − 1) / 2`) ;
- la clé publique reçue vérifie `1 < Y < p − 1` et `Y^q mod p = 1`, c'est-à-dire qu'elle est
  dans le groupe engendré par `g`. Sinon (attaque par **petit sous-groupe**), une valeur comme
  `1` ou `p − 1` ne laisserait que une ou deux valeurs possibles pour `S`.

## DH, ElGamal, et la vraie vie

- **ElGamal**, c'est Diffie-Hellman avec une paire de clés neuve (`r`, `g^r`) pour chaque
  message : seul le destinataire a une clé fixe.
- Ici, les deux clés sont fixes (DH *statique*) : si une clé privée fuit, tous les messages
  passés entre ces deux personnes deviennent lisibles. TLS utilise donc des clés DH
  éphémères, jetées après chaque connexion (*forward secrecy*).
- La structure « DH statique + chiffrement symétrique + tag » est celle de `crypto_box` (NaCl),
  avec X25519 à la place du groupe modulo `p`.
