# Authentification (`-a`) : HMAC-SHA256

Code : [`src/mac.py`](../src/mac.py), [`src/systems/base.py`](../src/systems/base.py)

```sh
./my_pgp xor|aes         -c|-d -a [-m ...] [-p] KEY
./my_pgp pgp-xor|pgp-aes -c|-d -a [-m ...] [-p ...] [-s] SYM:RSA_KEY
```

`-a` doit être donné **au chiffrement et au déchiffrement**. Il ne se combine pas avec `-b`.

## Pourquoi : chiffrer n'est pas protéger

Le chiffrement garantit la **confidentialité** (Eve ne lit pas), pas l'**intégrité** (Eve ne
modifie pas). Avec XOR ou AES-CTR, inverser un bit du chiffré inverse le même bit du message
déchiffré : Eve peut changer `pay 100 to Arya` en `pay 900 to Arya` sans connaître la clé.
Avec ECB, elle peut recopier, retirer ou réordonner des blocs.

Avec `-a`, une **empreinte secrète** (le tag) suit le chiffré : sans la clé, impossible de
fabriquer le tag d'un chiffré modifié.

## HMAC (RFC 2104)

```
HMAC(K, m) = SHA-256((K ⊕ opad) || SHA-256((K ⊕ ipad) || m))
K complétée par des 00 jusqu'à 64 octets (hachée d'abord si plus longue), ipad = 36…36, opad = 5c…5c
```

Pourquoi pas simplement `SHA-256(K || m)` ? SHA-256 traite le message bloc par bloc et
son résultat est son état interne : à partir de `SHA-256(K || m)` seul, on peut **continuer**
le calcul sur `m || bourrage || suite` sans connaître `K` (*length extension*). Les deux
hachages imbriqués de HMAC l'empêchent.

Le SHA-256 utilisé est celui du projet ([signature.md](signature.md)). `tests/test_mac.py`
vérifie HMAC sur le vecteur 2 de la RFC 4231 et le compare au module `hmac` de Python.

## Format : encrypt-then-MAC

```
sortie = hex(chiffré || tag)        tag = HMAC(K_mac, chiffré), 32 octets = les 64 derniers caractères
```

- Le tag couvre **tout** ce qui le précède, IV ou compteur compris (`-m cbc` / `-m ctr`).
- Au déchiffrement, le tag est vérifié **avant** de déchiffrer quoi que ce soit : un message
  modifié, tronqué ou une mauvaise clé donne une erreur (code 84, rien sur la sortie standard).
- C'est l'ordre recommandé (*encrypt-then-MAC*) : on ne déchiffre jamais une donnée non
  authentifiée, ce qui ferme la porte aux attaques par oracle de bourrage.

## La clé du tag

On ne se sert jamais de la même clé pour deux usages : la clé du tag est **dérivée** de la clé
symétrique (ses octets, peu importe comment l'hexadécimal est écrit) :

```
K_mac = HMAC("my_pgp authentication key", clé symétrique)       (HKDF-Extract, RFC 5869)
```

Le libellé est la clé de HMAC et la clé symétrique la donnée, pas l'inverse : HMAC complète sa
clé avec des `00`, donc `6b65` et `6b6500` seraient la même clé HMAC. Or c'est justement ce
que RSA fait à une clé PGP qui se termine par `00` ([pgp.md](pgp.md)). Dans ce sens-là, les deux
clés donnent deux tags différents, et l'erreur est détectée.

## Comparaison en temps constant

Le tag reçu est comparé **octet par octet jusqu'au bout**, même après une différence. S'arrêter
au premier octet faux répondrait plus vite pour un mauvais début : en mesurant le temps, un
attaquant pourrait deviner le tag octet par octet (*timing attack*).

## Avec PGP

Le tag est sur la ligne du message chiffré (ligne 2), calculé avec la clé symétrique. Sans
`-p`, une clé qui ne revient pas intacte de RSA (trop grande, ou finissant par `00`) donnait
un message faux sans erreur ; avec `-a`, c'est une erreur « invalid tag ». Avec `-s`, la
signature couvre aussi le tag.

## Limite

SHA-256 est écrit en Python pur : `-a` coûte environ 15 s pour 5 Mo, en plus du chiffrement.
