# Conventions communes

Ces règles s'appliquent à tous les systèmes de chiffrement du projet. La plupart des
surprises (« pourquoi ma sortie est à l'envers ? ») viennent de là.

## Tout est en hexadécimal

- Les **clés** passées en argument sont en hexadécimal (`6b6579`, `000102...`).
- Les **messages chiffrés** (sortie de `-c`, entrée de `-d`) sont en hexadécimal, sur une ligne
  terminée par `\n`.
- Les **messages clairs** sont des octets bruts lus sur l'entrée standard (texte ou binaire).

Une valeur hexadécimale est lue comme par `bytes.fromhex` : les blancs au début et à la fin
sont ignorés, ainsi que ceux placés **entre deux octets** (`6b 65 79`, ou un chiffré coupé
sur plusieurs lignes) ; les majuscules sont acceptées. Un blanc au milieu d'un octet
(`6 b`), un nombre impair de chiffres ou un caractère hors `0-9a-fA-F` est une erreur. Une
valeur vide vaut zéro octet (le nombre 0). La sortie est toujours en minuscules.

## Little-endian

Les nombres et les clés sont lus en **little-endian** : le premier octet écrit est l'octet de
poids faible.

| hexadécimal | valeur      |
|-------------|-------------|
| `01`        | 1           |
| `0001`      | 256         |
| `010001`    | 65537       |
| `d3`        | 211         |

Conséquences :
- un octet `00` **à la fin** d'un nombre ne change pas sa valeur (`6b65` et `6b6500` valent
  la même chose) ; quand le programme réécrit ce nombre, il produit la forme minimale
  (`6b65`). C'est ce qui pose problème dans PGP, voir [pgp.md](pgp.md).
- chaque système applique cette convention à sa façon (inversion de toute la clé pour XOR,
  inversion par mots de 4 octets pour AES) : voir les pages dédiées.

## Entrée standard

Pour tous les systèmes du sujet et dans tous les modes, **un seul** `\n` final sur l'entrée
est ignoré (celui ajouté par `echo`) : il ne fait pas partie du message. Un `\r` ou un second
`\n` en font partie.

Exception : `elgamal` chiffre l'entrée **telle quelle** et rend exactement les octets
déchiffrés, pour qu'un fichier fasse l'aller-retour à l'identique (voir [elgamal.md](elgamal.md)).

## Mode bloc (`-b`) et mode flux

**Mode bloc** (`-b`, XOR / AES / PGP) :
- le message doit faire **exactement** la taille d'un bloc (taille de la clé pour XOR,
  16 octets pour AES), sinon erreur ;
- le déchiffrement ajoute un `\n` à la sortie.

**Mode flux** (sans `-b`) :
- le message est découpé en blocs ; le dernier est **complété avec des octets nuls** ;
- chaque bloc est chiffré indépendamment (mode ECB) : deux blocs identiques donnent deux
  blocs chiffrés identiques ;
- au déchiffrement, le chiffré est découpé de la même façon : si sa taille n'est pas un
  multiple du bloc, le dernier morceau est lui aussi complété avec des `00` ;
- la sortie déchiffrée contient **tous** les octets déchiffrés, bourrage `00` compris, suivis
  d'un `\n` (une entrée vide donne donc juste `\n`).

Avec `-p`, le bourrage est PKCS#7 et il est retiré au déchiffrement : le message revient
exactement (voir [padding.md](padding.md)). `-p` ne se combine pas avec `-b`.

Avec `-m cbc` ou `-m ctr` (AES), les blocs sont enchaînés au lieu d'être chiffrés
indépendamment, et l'IV ou le compteur précède le chiffré (voir [modes.md](modes.md)). Avec
`-a`, un tag HMAC de 32 octets suit le chiffré (voir [authentication.md](authentication.md)).
Ni l'un ni l'autre ne se combine avec `-b`.

## Erreurs

En cas d'erreur, le programme écrit `my_pgp: <message>` sur la sortie d'erreur, rien sur la
sortie standard, et renvoie le code **84**. En cas de succès il renvoie **0**.
