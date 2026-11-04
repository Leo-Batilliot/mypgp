# Signatures (`-s`)

Code : [`src/sha256.py`](../src/sha256.py), [`src/padding.py`](../src/padding.py)
(`emsa_encode`), `RsaKey.sign` / `RsaKey.verify` dans [`src/systems/rsa.py`](../src/systems/rsa.py).

## À quoi ça sert

Le chiffrement protège la **confidentialité** : Euron ne peut pas lire le message. Mais
n'importe qui peut chiffrer avec la clé publique de Brienne : rien ne prouve que le message
vient d'Arya, ni qu'il n'a pas été modifié en route. La signature apporte :

- l'**authenticité** : seul le détenteur de la clé privée de signature peut signer ;
- l'**intégrité** : changer un seul bit du message chiffré rend la signature fausse.

Signer, c'est « chiffrer avec la clé privée » : tout le monde peut vérifier avec la clé
publique, personne d'autre ne peut produire la signature.

## Utilisation

`-s` est disponible avec `rsa`, `pgp-xor` et `pgp-aes`, et doit être donné **au chiffrement
et au déchiffrement**. La clé reçoit un composant de plus : la clé RSA du signataire
(Arya), différente de celle du destinataire (Brienne).

| commande       | clé                                                   |
|----------------|-------------------------------------------------------|
| `rsa -c -s`    | `CLE_PUBLIQUE_DESTINATAIRE:CLE_PRIVEE_SIGNATAIRE`     |
| `rsa -d -s`    | `CLE_PRIVEE_DESTINATAIRE:CLE_PUBLIQUE_SIGNATAIRE`     |
| `pgp-* -c -s`  | `CLE_SYM:CLE_PUBLIQUE_DESTINATAIRE:CLE_PRIVEE_SIGNATAIRE` |
| `pgp-* -d -s`  | `CLE_SYM_CHIFFREE:CLE_PRIVEE_DESTINATAIRE:CLE_PUBLIQUE_SIGNATAIRE` |

La signature est écrite sur une **dernière ligne**, après la sortie habituelle. Au
déchiffrement, l'entrée est le message chiffré suivi de cette ligne. La signature est
**vérifiée avant de déchiffrer** : si elle est fausse, erreur (code 84) et rien sur la sortie.

```sh
$ ./my_pgp rsa -g 4b1d...86e1 bb3c...66cb          # Brienne (destinataire)
$ ./my_pgp rsa -g d5da...53e1 4fbd...4fe1          # Arya (signataire)
$ echo "All men must die" | ./my_pgp pgp-aes -c -s 5769...6e67:<public Brienne>:<privée Arya> > out
$ head -1 out                                      # clé AES chiffrée
$ tail -n +2 out | ./my_pgp pgp-aes -d -s <clé AES chiffrée>:<privée Brienne>:<publique Arya>
All men must die
```

## Ce qui est signé

On signe **le message chiffré** (« encrypt-then-sign », comme le demande le sujet) :

- `rsa` : le nombre chiffré `c` (ses octets little-endian) ;
- `pgp` : la clé symétrique chiffrée **et** le message chiffré :
  `longueur(clé chiffrée) sur 4 octets || clé chiffrée || message chiffré`.
  Sans la longueur, on pourrait déplacer des octets de la clé vers le message en gardant
  la même suite d'octets, donc la même signature.

Les données sont relues en hexadécimal puis réécrites sous forme minimale avant la
vérification : des blancs ou des majuscules en plus ne cassent pas la signature, mais tout
changement de valeur la casse.

## Comment : RSASSA-PKCS1-v1_5 avec SHA-256

1. **Hacher** : `H = SHA-256(données)`, 32 octets. On ne signe pas le message entier
   (il peut être plus grand que `n`) mais son empreinte ; trouver un autre message de même
   empreinte est infaisable.
2. **Encoder** (EMSA-PKCS1-v1_5) dans un bloc de la taille de `n` :
   ```
   EM = 00 || 01 || FF ... FF || 00 || DigestInfo || H
   ```
   `DigestInfo` (19 octets) dit « ce qui suit est un SHA-256 ». Le remplissage par `FF`
   empêche de fabriquer des signatures à partir de petites valeurs.
3. **Signer** : `s = EM^d mod n` (clé privée du signataire).
4. **Vérifier** : `s^e mod n` doit redonner exactement l'`EM` recalculé à partir des
   données reçues.

Contrairement au chiffrement, il n'y a pas d'aléatoire : la même donnée signée par la même
clé donne toujours la même signature (ce qui permet de la comparer à un oracle dans les
tests, voir `tests/test_signature.py`).

Il faut `n` d'au moins **62 octets** (`19 + 32 + 11`) : les premiers de 256 bits de
l'annexe suffisent (64 octets), pas ceux de 8 ou 32 bits.

Pourquoi deux paires de clés : la clé de Brienne sert à **chiffrer pour Brienne**, celle
d'Arya à **prouver que c'est Arya**. Utiliser la même paire pour les deux rôles est une
mauvaise pratique (signer revient à « déchiffrer » une valeur choisie).

## SHA-256

Implémenté à la main (FIPS 180-4), sans `hashlib` :

- le message est complété par `80`, des `00`, puis sa longueur en bits sur 8 octets, jusqu'à
  un multiple de 64 octets ;
- chaque bloc de 64 octets passe dans 64 tours qui mélangent un état de 8 mots de 32 bits
  (rotations, `XOR`, fonctions « choose » et « majority », additions modulo `2^32`) ;
- les constantes ne sont pas recopiées : ce sont les 32 premiers bits des parties
  fractionnaires des racines carrées (état initial) et cubiques (`K`) des premiers nombres
  premiers, calculées par le programme. Des constantes « sans rien dans la manche ».

Vérifié contre les vecteurs FIPS et contre `hashlib` dans `tests/test_sha256.py`.
