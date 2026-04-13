# Rapport — Sécurisation d'une messagerie instantanée

**Module** : Cryptographie  
**Date de rendu** : 15 avril 2026  
**Soutenance** : 20 avril 2026

---

## Table des matières

1. [Architecture du projet](#1-architecture-du-projet)
2. [Étape 3.1 — Chiffrement ROT13](#2-étape-31--chiffrement-rot13)
3. [Étape 3.2 — Chiffrement symétrique AES/CTR](#3-étape-32--chiffrement-symétrique-aesctr)
4. [Étape 3.3 — Intégrité avec AES-GCM](#4-étape-33--intégrité-avec-aes-gcm)
5. [Étape 3.4 — Échange de clés ECDH](#5-étape-34--échange-de-clés-ecdh)
6. [Étape 3.5 — Authentification ECDSA](#6-étape-35--authentification-ecdsa)
7. [Étape 3.6 — Infrastructure à clé publique (PKI)](#7-étape-36--infrastructure-à-clé-publique-pki)
8. [Étape 3.7 — Attaques résiduelles et Perfect Forward Secrecy](#8-étape-37--attaques-résiduelles-et-perfect-forward-secrecy)
9. [Bilan et conclusion](#9-bilan-et-conclusion)

---

## 1. Architecture du projet

### Structure des fichiers

```
CryptoChat/
├── Client.java           # Application cliente (TCP + threads)
├── Server.java           # Serveur de relais TCP
├── Interceptor.java      # Module cryptographique côté client
├── ServerInterceptor.java# Module d'attaque côté serveur (simulation MitM)
├── start.bat             # Script de lancement
├── client1_private.pem   # Clé privée ECDSA de Client 1
├── client1_cert.pem      # Certificat X.509 de Client 1 (signé par CA)
├── client2_private.pem   # Clé privée ECDSA de Client 2
├── client2_cert.pem      # Certificat X.509 de Client 2 (signé par CA)
├── ca_cert.pem           # Certificat auto-signé de l'autorité de certification
└── ca_private.pem        # Clé privée de la CA (à protéger)
```

### Rôles des composants

- **`Client.java`** : établit une connexion TCP vers le serveur (port 8888), lance deux threads — un pour l'envoi et un pour la réception des messages. Avant tout échange, il déclenche le handshake cryptographique via `Interceptor.onHandshake()`.

- **`Interceptor.java`** : contient toute la logique cryptographique côté client — handshake ECDH+PKI, chiffrement/déchiffrement AES-GCM, vérification des certificats, compteurs de séquence.

- **`Server.java`** : accepte exactement deux clients, leur envoie un signal `READY` quand les deux sont connectés, puis relaie les messages de l'un vers l'autre via `ServerInterceptor.onMessageRelay()`.

- **`ServerInterceptor.java`** : point d'injection pour simuler des attaques MitM. Son comportement change à chaque étape du projet.

### Niveau de sécurité visé

Toutes les primitives utilisées visent **128 bits de sécurité** :
- Courbe elliptique **secp256r1** (P-256)
- Chiffrement symétrique **AES-128**
- Hachage **SHA-256** pour la dérivation de clé
- Signatures **SHA256withECDSA**

### Flux d'une session complète

Voici la séquence chronologique des opérations pour une conversation entre Client 1 et Client 2, dans l'état final du projet :

```
Client 1                          Server                         Client 2
   |                                 |                               |
   |------- connexion TCP --------->|<------- connexion TCP --------|
   |                                 |                               |
   |<---------- "READY" ------------|------------- "READY" -------->|
   |                                 |                               |
   |== HANDSHAKE =================================================================================|
   |                                 |                               |
   | génère paire ECDH éphémère      |         génère paire ECDH éphémère                        |
   | signe ecdhPub avec ECDSA priv   |         signe ecdhPub avec ECDSA priv                     |
   |                                 |                               |
   |-- Base64(ecdhPub|sig|cert) ---->|-- Base64(ecdhPub|sig|cert) -->|
   |<-- Base64(ecdhPub|sig|cert) ----|<-- Base64(ecdhPub|sig|cert) --|
   |                                 |                               |
   | vérifie cert avec ca_cert.pem   |         vérifie cert avec ca_cert.pem                     |
   | vérifie signature ECDSA         |         vérifie signature ECDSA                           |
   | dérive sessionKey (ECDH+SHA256) |         dérive sessionKey (ECDH+SHA256)                   |
   |                                 |                               |
   |== MESSAGES =================================================================================|
   |                                 |                               |
   | prefixe seq=0, chiffre GCM      |                               |
   |-- Base64(IV||ct+tag) ---------->|-- Base64(IV||ct+tag) -------->|
   |                                 |                 déchiffre, vérifie seq=0 attendu           |
   |                                 |                               |
   | prefixe seq=1, chiffre GCM      |                               |
   |-- Base64(IV||ct+tag) ---------->|-- Base64(IV||ct+tag) -------->|
   |                                 |                 déchiffre, vérifie seq=1 attendu           |
```

**Sens unique du compteur** : `sendCounter` et `recvCounter` sont indépendants. Client 1 compte ses envois (0, 1, 2...) et Client 2 vérifie que ce qu'il reçoit correspond à son `recvCounter` (0, 1, 2...). Les messages de Client 2 vers Client 1 ont leurs propres compteurs.

### Pourquoi tout passe par Server.java

La connexion est en étoile : les deux clients ne communiquent jamais directement. Tous les messages transitent par le serveur. Cela est réaliste (Internet est un réseau de relais) et permet de simuler facilement un attaquant en modifiant uniquement `ServerInterceptor.java`, sans toucher au code des clients.

---

## 2. Étape 3.1 — Chiffrement ROT13

### Principe

ROT13 (Rotate by 13) est un **chiffrement par substitution monoalphabétique** : il remplace chaque lettre par celle qui se trouve 13 positions plus loin dans l'alphabet (cyclique sur 26 lettres). Puisque l'alphabet fait 26 lettres, appliquer ROT13 deux fois redonne le texte original : ROT13(ROT13(x)) = x.

Exemple :
```
Texte clair  : "Bonjour Alice"
ROT13        : "Obawhbe Nyvpr"
ROT13 à nouveau : "Bonjour Alice"
```

ROT13 appartient à la famille des **chiffres de César** (substitution avec décalage fixe). Le chiffre de César originel utilisait un décalage de 3 ; ROT13 utilise 13.

### Principe de Kerckhoffs et pourquoi ROT13 viole ce principe

Le **principe de Kerckhoffs** (1883) stipule qu'un système cryptographique doit rester sûr même si tout est connu de l'algorithme, *sauf la clé*. ROT13 n'a pas de clé : l'algorithme *est* la clé. Ainsi :

- Aucune information secrète n'est nécessaire pour déchiffrer
- L'algorithme étant public et sans paramètre, la confidentialité est nulle
- Ce n'est pas du chiffrement au sens cryptographique moderne, c'est de l'obfuscation

### Pourquoi c'est insuffisant

ROT13 n'offre aucune sécurité réelle : l'algorithme est universellement connu et ne nécessite aucune clé. N'importe quel attaquant peut déchiffrer un message ROT13 sans aucune information secrète. De plus, la **distribution des fréquences** des lettres est préservée : les méthodes d'analyse fréquentielle (attaque statistique) permettent de casser même des substitutions inconnues avec suffisamment de texte chiffré.

### Démonstration de l'attaque

Le `ServerInterceptor` interceptait les messages et leur appliquait ROT13 une deuxième fois pour retrouver le texte clair, avant de les retransmettre à l'autre client. L'attaque est **passive et transparente** : Client 2 reçoit le message correct, personne ne remarque que l'attaquant a tout lu.

```java
// ServerInterceptor en mode 3.1 — trivial à implémenter
public String onMessageRelay(String message, boolean fromClient1) {
    System.out.println("[ATTAQUE PASSIVE] Message en clair : " + rot13(message));
    return message; // retransmis sans modification
}
```

Cette étape illustre pourquoi on a besoin d'un vrai chiffrement avec une clé secrète.

---

## 3. Étape 3.2 — Chiffrement symétrique AES/CTR

### Objectif

Remplacer ROT13 par un chiffrement symétrique réel. Le mot de passe est saisi par l'utilisateur au lancement du client (`args[0]`), puis transformé en clé AES-128.

### Comment fonctionne AES

AES (Advanced Encryption Standard, FIPS 197) est un **chiffrement par blocs** qui opère sur des blocs de 128 bits (16 octets). La clé fait 128, 192 ou 256 bits (ici 128 bits). AES réalise 10 tours de substitutions, permutations et mélanges de colonnes (SubBytes, ShiftRows, MixColumns, AddRoundKey). Sa sécurité repose sur la diffusion et la confusion : un seul bit changé dans la clé ou le texte clair modifie en moyenne la moitié des bits du texte chiffré.

AES seul chiffre exactement un bloc de 16 octets. Pour chiffrer des messages de longueur arbitraire, on utilise un **mode d'opération**.

### Mode CTR — `AES/CTR/NoPadding`

```java
Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
```

Le mode CTR (Counter) transforme AES en un **chiffrement de flux** :

1. On construit un bloc compteur = IV (8 octets) || compteur (8 octets, incrémenté à chaque bloc)
2. On chiffre ce bloc compteur avec AES → on obtient un bloc de "keystream" de 16 octets
3. On XOR le keystream avec le texte clair (16 octets à la fois)
4. On incrémente le compteur pour le prochain bloc

```
Bloc 1 : AES_K(IV || 0) XOR plaintext[0:16]  = ciphertext[0:16]
Bloc 2 : AES_K(IV || 1) XOR plaintext[16:32] = ciphertext[16:32]
...
```

**Pourquoi CTR ?**
- **NoPadding** : puisque le XOR s'applique octet par octet, il n'y a pas besoin de compléter le dernier bloc — contrairement à CBC/ECB qui nécessitent du padding.
- **Parallélisable** : chaque bloc est indépendant, on peut les traiter en parallèle.
- L'IV de 16 octets est généré aléatoirement à chaque message avec `SecureRandom` (indispensable : réutiliser le même IV avec la même clé permettrait à un attaquant de calculer le XOR des deux textes clairs).

### Dérivation de clé — `SHA-256`

```java
MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
byte[] hash = sha256.digest(password.getBytes(StandardCharsets.UTF_8));
byte[] keyBytes = Arrays.copyOf(hash, 16); // 16 octets = 128 bits
SecretKey key = new SecretKeySpec(keyBytes, "AES");
```

**Pourquoi SHA-256 ?** On ne peut pas utiliser directement un mot de passe comme clé AES car sa longueur est variable et sa distribution n'est pas uniforme. SHA-256 produit un condensé de 256 bits à distribution pseudo-aléatoire. On en prend les 16 premiers octets pour obtenir une clé AES-128.

SHA-256 est une **fonction à sens unique** : il est impossible (en pratique) de retrouver le mot de passe à partir du condensé. Deux mots de passe différents produisent des condensés complètement différents (effet avalanche).

**Limite** : SHA-256 seul n'est pas une fonction de dérivation de clé robuste : pas de sel (vulnérable aux attaques par table arc-en-ciel) et pas d'itérations (rapide à brute-forcer). En production on utiliserait PBKDF2 ou Argon2, mais pour ce projet cela suffit.

### Démonstration de l'attaque — bit flip

Le mode CTR n'offre **aucune intégrité**. Sa propriété malléable : modifier un bit i du texte chiffré modifie exactement le bit i du texte déchiffré.

**Mathématiquement** : `CT[i] = PT[i] XOR KS[i]` donc `PT[i] = CT[i] XOR KS[i]`. Si on remplace `CT[i]` par `CT[i] XOR 1`, le déchiffrement donne `PT[i] XOR 1` — le bit est flipé.

```java
// ServerInterceptor en mode 3.2 — bit flip ciblé
public String onMessageRelay(String message, boolean fromClient1) {
    byte[] data = Base64.getDecoder().decode(message);
    data[30] ^= 0x20; // flip du bit 5 de l'octet 30 (dans le ciphertext)
    return Base64.getEncoder().encodeToString(data);
}
```

Un attaquant qui connaît la position et le contenu attendu du texte clair peut modifier un caractère précis de manière ciblée. Le client déchiffre et affiche le message corrompu sans aucune erreur car AES/CTR ne contient pas de mécanisme de détection de tampering.

---

## 4. Étape 3.3 — Intégrité avec AES-GCM

### Objectif

Remplacer AES/CTR par un mode **AEAD** (Authenticated Encryption with Associated Data) qui garantit à la fois la confidentialité et l'intégrité du message.

### Problème fondamental de CTR : séparation chiffrement / intégrité

AES/CTR assure la confidentialité mais pas l'intégrité. En 3.2, on aurait pu ajouter un HMAC séparé (Encrypt-then-MAC), mais cela introduit de la complexité et des risques d'erreur de composition. La bonne pratique moderne est d'utiliser un mode AEAD qui gère les deux en un seul appel.

### Qu'est-ce que l'AEAD ?

Un mode AEAD garantit deux propriétés simultanément :
- **Confidentialité** : le texte chiffré ne révèle rien sur le texte clair (sous réserve de ne pas réutiliser l'IV)
- **Authenticité/Intégrité** : toute modification du texte chiffré est détectée lors du déchiffrement — même un seul bit modifié invalide le message

La notion "with Associated Data" permet d'authentifier des métadonnées non chiffrées (par exemple des en-têtes), mais nous ne l'utilisons pas ici.

### Comment fonctionne GCM internement

GCM (Galois/Counter Mode) est composé de deux couches :

1. **Couche de chiffrement (CTR)** : identique au mode CTR précédent, elle chiffre le texte clair avec la keystream dérivée d'AES.

2. **Couche d'authentification (GHASH)** : une fonction polynomiale dans le corps de Galois GF(2¹²⁸) qui calcule un code d'authentification de message (MAC) sur le texte chiffré. Le tag final est : `T = GHASH(H, A, C) XOR AES_K(J0)` où H = AES_K(0), J0 = IV||0001, A = associated data, C = ciphertext.

L'important à retenir : le tag de 128 bits couvre **tous les octets du texte chiffré**. Modifier n'importe quel octet change le tag attendu.

### Mode GCM — `AES/GCM/NoPadding`

```java
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
cipher.init(Cipher.ENCRYPT_MODE, sessionKey, new GCMParameterSpec(128, iv));
byte[] ct = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
```

**`GCMParameterSpec(128, iv)`** : le premier paramètre est la longueur du tag en bits (128 = maximum = plus sécurisé), le second est l'IV.

**`doFinal()`** : lors du chiffrement, appende les 16 octets du tag en fin du tableau retourné. Lors du déchiffrement, vérifie le tag avant de retourner le texte clair — si le tag est invalide, lève `AEADBadTagException`. Cela garantit qu'on ne manipule jamais un texte clair non authentifié.

**IV de 12 octets** : le standard NIST recommande un IV de 96 bits (12 octets) pour GCM car c'est la taille optimale pour la construction interne. Un IV de 16 octets nécessiterait un traitement supplémentaire (hachage GHASH de l'IV) qui réduirait les performances sans bénéfice de sécurité.

**Pourquoi l'IV doit être unique** : si le même IV est utilisé deux fois avec la même clé, un attaquant peut XOR les deux textes chiffrés pour annuler la keystream, et la sécurité du tag est compromise. C'est pourquoi on génère un nouvel IV aléatoire (`SecureRandom`) à chaque message.

```java
// Format du message transmis : IV (12 octets) || ciphertext+tag
byte[] out = new byte[iv.length + ct.length];
System.arraycopy(iv, 0, out, 0, iv.length);
System.arraycopy(ct, 0, out, iv.length, ct.length);
return Base64.getEncoder().encodeToString(out);
```

Le tout est encodé en **Base64** pour transmission sur le canal texte (socket TCP avec `PrintWriter`). Base64 convertit des octets arbitraires en caractères ASCII imprimables (A-Z, a-z, 0-9, +, /), nécessaire car `PrintWriter.println()` attend du texte.

### Déchiffrement et vérification du tag

```java
byte[] data = Base64.getDecoder().decode(received);
byte[] iv = Arrays.copyOfRange(data, 0, 12);        // premiers 12 octets = IV
byte[] ct = Arrays.copyOfRange(data, 12, data.length); // reste = ciphertext + tag
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
cipher.init(Cipher.DECRYPT_MODE, sessionKey, new GCMParameterSpec(128, iv));
byte[] plaintext = cipher.doFinal(ct); // lève AEADBadTagException si tag invalide
```

### Démonstration

Le `ServerInterceptor` tentait la même attaque bit-flip qu'en 3.2. Cette fois, le client recevait `[Decryption failed: Tag mismatch]` — l'intégrité était garantie.

La raison précise : en modifiant un octet du texte chiffré, le tag recalculé lors du déchiffrement ne correspond plus au tag annexé par l'émetteur. `doFinal()` détecte cette incohérence et refuse de retourner le texte clair.

---

## 5. Étape 3.4 — Échange de clés ECDH

### Objectif

Les étapes 3.2 et 3.3 supposaient que les deux clients connaissaient un mot de passe commun à l'avance. C'est le **problème de distribution de clé** : comment partager un secret sur un canal non sécurisé ? ECDH résout ce problème.

### Rappel : Diffie-Hellman

Le protocole Diffie-Hellman (DH, 1976) permet à deux parties d'établir un secret commun en échangeant des informations publiques, sans qu'un observateur puisse calculer ce secret. Il repose sur un problème mathématique difficile.

La version classique (DH sur entiers modulo un grand premier) a été remplacée par la version sur courbes elliptiques (ECDH) car elle offre le même niveau de sécurité avec des clés beaucoup plus courtes (256 bits au lieu de 3072 bits pour 128 bits de sécurité), ce qui réduit la taille des messages et la charge de calcul.

### Courbes elliptiques — intuition

Une courbe elliptique est une courbe définie par une équation du type $y^2 = x^3 + ax + b$ sur un corps fini. Les points de cette courbe ont une loi d'addition géométrique (point + point = point). La **multiplication scalaire** $k \cdot P$ (additionner P avec lui-même k fois) est facile à calculer mais impossible à inverser : connaître $P$ et $k \cdot P$, retrouver $k$ est le **problème du logarithme discret sur courbe elliptique (ECDLP)**, considéré calculatoirement insoluble pour des courbes bien choisies.

### Pourquoi secp256r1 (P-256)

secp256r1 est la courbe la plus standardisée, définie par le NIST (FIPS 186-4) et recommandée par l'ANSSI. Elle offre **128 bits de sécurité** — le meilleur algorithme connu pour casser ECDLP sur cette courbe nécessite environ $2^{128}$ opérations. L'ordre de la courbe (nombre de points) est un entier premier de 256 bits, ce qui garantit des propriétés cryptographiques optimales.

### Génération de la paire ECDH éphémère

```java
KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
kpg.initialize(new ECGenParameterSpec("secp256r1"));
KeyPair ecdhKeyPair = kpg.generateKeyPair();
```

`KeyPairGenerator.getInstance("EC")` : "EC" est le nom de l'algorithme dans le JCE (Java Cryptography Extension). Il délègue à un `Provider` (par défaut `SunEC`) qui implémente la génération de clés EC.

`ECGenParameterSpec("secp256r1")` : spécifie la courbe à utiliser parmi toutes celles supportées par Java. D'autres noms acceptés : "P-256", "prime256v1".

`generateKeyPair()` : génère aléatoirement un entier $k$ (clé privée) dans $[1, n-1]$ où $n$ est l'ordre de la courbe, puis calcule $K = k \cdot G$ (clé publique, G étant le point générateur).

**Pourquoi "éphémère" ?** La paire de clés est générée à chaque nouvelle session et n'est jamais sauvegardée sur disque. Cela garantit la Perfect Forward Secrecy (voir 3.7.3).

### Protocole d'échange pendant le handshake

```
Client 1                                      Client 2
génère (priv1, pub1)                          génère (priv2, pub2)
envoie Base64(pub1.getEncoded())  --------->
                                  <--------- envoie Base64(pub2.getEncoded())
calcule secret = ECDH(priv1, pub2)            calcule secret = ECDH(priv2, pub1)
```

Les deux calculs produisent le même secret car ECDH(priv1, pub2) = priv1 × pub2 = priv1 × (priv2 × G) = priv2 × (priv1 × G) = priv2 × pub1 = ECDH(priv2, pub1).

### Calcul du secret partagé

```java
KeyAgreement ka = KeyAgreement.getInstance("ECDH");
ka.init(ecdhKeyPair.getPrivate());
ka.doPhase(otherEcdhPub, true);
byte[] sharedSecret = ka.generateSecret();
```

`ka.doPhase(otherEcdhPub, true)` : le deuxième paramètre `true` indique que c'est la dernière (et unique) phase — ECDH est un protocole à une seule phase (contrairement à certains autres protocoles).

`generateSecret()` : retourne les coordonnées x du point résultant (32 octets pour P-256), qui constitue le secret partagé.

### Dérivation de la clé de session AES-128

```java
MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
sessionKey = new SecretKeySpec(Arrays.copyOf(sha256.digest(sharedSecret), 16), "AES");
```

Le secret ECDH brut n'est pas directement utilisable comme clé AES : sa distribution n'est pas uniforme car c'est une coordonnée de point de courbe elliptique. SHA-256 le transforme en une valeur pseudo-aléatoire de 256 bits, dont on prend les 16 premiers octets pour AES-128.

### Démonstration de l'attaque MitM ECDH

Sans authentification des clés publiques, le `ServerInterceptor` pouvait intercepter les clés ECDH de chaque client et les remplacer par les siennes. Il établissait ainsi deux sessions distinctes :

- **K1** = ECDH(mitmPrivKey1, clientPub1) → partagée avec Client 1
- **K2** = ECDH(mitmPrivKey2, clientPub2) → partagée avec Client 2

Il pouvait déchiffrer tous les messages avec K1, les lire en clair, puis les re-chiffrer avec K2 pour Client 2. Les clients ne détectaient rien.

**Pourquoi les clients ne détectent pas** : les clients voient une clé publique ECDH, la traitent, dérivent une clé, chiffrent et déchiffrent correctement. Rien dans le protocole ne leur dit si la clé publique reçue appartient vraiment au bon interlocuteur. L'absence d'**authentification** est la faille.

---

## 6. Étape 3.5 — Authentification ECDSA

### Objectif

Authentifier les clés ECDH éphémères pour empêcher leur substitution par un MitM. Chaque client possède une paire de clés **ECDSA** long terme, stockée dans des fichiers PEM.

### Distinction ECDH / ECDSA

Il est important de distinguer les deux paires de clés utilisées :

| Paire | Usage | Durée de vie |
|-------|-------|--------------|
| ECDH éphémère | Dériver la clé de session AES | Une seule session — générée en mémoire |
| ECDSA long terme | Signer / authentifier | Permanent — stockée dans des fichiers PEM |

Les clés ECDSA (dans les fichiers `.pem`) ne chiffrent jamais. Elles servent uniquement à **prouver l'identité** du client.

### Comment fonctionne ECDSA

ECDSA (Elliptic Curve Digital Signature Algorithm) permet de signer un message :

1. **Signature** (avec la clé privée) :
   - Calcule $e = \text{SHA-256}(message)$
   - Génère un entier aléatoire $k$ (nonce de signature, unique à chaque signature)
   - Calcule $R = k \cdot G$, $r = R.x \bmod n$
   - Calcule $s = k^{-1}(e + r \cdot \text{privKey}) \bmod n$
   - La signature est la paire $(r, s)$

2. **Vérification** (avec la clé publique) :
   - Recalcule $e = \text{SHA-256}(message)$
   - Vérifie que $r \equiv (s^{-1}(e \cdot G + r \cdot \text{pubKey})).x \pmod{n}$

La vérification prouve que seul le détenteur de `privKey` a pu produire cette signature, sans que cette clé privée ne soit jamais transmise.

**Important** : le nonce $k$ doit être aléatoire et unique à chaque signature. Réutiliser $k$ deux fois permet de retrouver la clé privée. Java gère cela automatiquement avec `SecureRandom` en interne.

### Génération des clés avec OpenSSL

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out client1_private.pem
openssl ec -in client1_private.pem -pubout -out client1_public.pem
```

Les clés privées sont au format **PKCS8 PEM** (`-----BEGIN PRIVATE KEY-----`), les clés publiques au format **X.509 SubjectPublicKeyInfo PEM** (`-----BEGIN PUBLIC KEY-----`). Java lit ces formats nativement avec `PKCS8EncodedKeySpec` et `X509EncodedKeySpec`.

**Chargement de la clé privée en Java** :

```java
// Lire le fichier PEM, enlever les en-têtes et décoder en Base64
String pem = new String(Files.readAllBytes(Path.of(path)));
String b64 = pem.replace("-----BEGIN PRIVATE KEY-----", "")
               .replace("-----END PRIVATE KEY-----", "")
               .replaceAll("\\s", "");
byte[] der = Base64.getDecoder().decode(b64);
PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
ecdsaPrivateKey = KeyFactory.getInstance("EC").generatePrivate(spec);
```

`PKCS8EncodedKeySpec` contient l'encodage DER de la clé privée tel que défini par le standard PKCS#8 (RFC 5958). `KeyFactory` reconstruit l'objet `PrivateKey` Java depuis ces bytes.

### Protocole de handshake 3.5

Chaque client envoie : `Base64(ecdhPub) | Base64(sig) | Base64(ecdsaPub)`

- **`ecdhPub`** : clé publique ECDH éphémère (à utiliser pour dériver la session)
- **`sig`** : signature SHA256withECDSA de ecdhPub avec la clé ECDSA long terme
- **`ecdsaPub`** : clé publique ECDSA (pour vérifier la signature)

```java
// Signature de la clé ECDH
Signature sig = Signature.getInstance("SHA256withECDSA");
sig.initSign(ecdsaPrivateKey);
sig.update(ecdhPubBytes);
byte[] signature = sig.sign();

// Vérification côté destinataire
Signature verifier = Signature.getInstance("SHA256withECDSA");
verifier.initVerify(otherEcdsaPub);
verifier.update(otherEcdhPubBytes);
boolean valid = verifier.verify(otherSig);
```

Le destinataire sait que `ecdhPub` a bien été produit par le détenteur de `ecdsaPriv` correspondant à `ecdsaPub`.

### Limite de cette approche

La signature prouve que `ecdhPub` a bien été signé par le détenteur de `ecdsaPrivate`. Mais rien ne prouve **à qui appartient** cette clé ECDSA. Le MitM peut générer sa propre paire ECDSA, signer sa propre clé ECDH, et les clients accepteront la signature — elle est valide, mais la clé ECDSA est inconnue. **Sans PKI, on ne peut pas résoudre ce problème.**

**Analogie** : recevoir une lettre signée prouve que la même personne a écrit et signé. Mais si on ne sait pas à qui appartient la signature, on ne peut pas vérifier l'identité de l'expéditeur.

Le `ServerInterceptor` générait ses propres paires ECDSA, signait ses clés ECDH avec, et transmettait tout aux clients. Les clients vérifiaient la signature (valide) sans pouvoir détecter l'usurpation.

---

## 7. Étape 3.6 — Infrastructure à clé publique (PKI)

### Objectif

Lier cryptographiquement une identité (CN=Client1) à une clé publique ECDSA grâce à une **autorité de certification (CA)** tierce de confiance.

### Problème résolu

En 3.5, le client reçoit une clé publique ECDSA et lui fait confiance pour vérifier une signature — mais il ne sait pas à qui appartient cette clé. La PKI résout ce problème en introduisant un tiers de confiance (la CA) qui **certifie** l'appartenance d'une clé à une identité.

### Qu'est-ce qu'un certificat X.509

Un certificat X.509 est un document structuré (format ASN.1, encodage DER) qui contient :
- **Subject** : l'identité certifiée (ex. `CN=Client1`)
- **SubjectPublicKeyInfo** : la clé publique ECDSA du sujet
- **Issuer** : l'identité de la CA qui a signé (`CN=CryptoChat CA`)
- **Validity** : période de validité (here 365 jours)
- **Signature** : la signature de la CA sur tous les champs précédents

Quiconque fait confiance à la CA peut vérifier que la signature dans le certificat est valide, ce qui prouve que la CA atteste de l'appartenance de cette clé publique à cette identité.

### Génération de la PKI avec OpenSSL

```bash
# 1. Créer la CA (clé + certificat auto-signé)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca_private.pem
openssl req -new -x509 -key ca_private.pem -out ca_cert.pem -days 365 -subj "/CN=CryptoChat CA"
```

`-x509` : génère directement un certificat auto-signé (la CA se certifie elle-même). Le certificat de la CA est la **racine de confiance** (trust anchor) : on l'accepte a priori car c'est nous qui l'avons créé.

```bash
# 2. Créer une CSR (Certificate Signing Request) pour Client 1
openssl req -new -key client1_private.pem -out client1_csr.pem -subj "/CN=Client1"
```

Une **CSR** est une demande de certification : elle contient l'identité souhaitée et la clé publique à certifier, signée par la clé privée correspondante (preuve de possession). La CA reçoit cette CSR, vérifie l'identité, et émet un certificat.

```bash
# 3. La CA signe la CSR → émet le certificat
openssl x509 -req -in client1_csr.pem -CA ca_cert.pem -CAkey ca_private.pem -CAcreateserial -out client1_cert.pem -days 365
```

`-CAcreateserial` : crée un fichier `.srl` contenant le numéro de série du dernier certificat émis (les numéros de série doivent être uniques par CA).

### Chaîne de confiance

```
ca_cert.pem (auto-signé, trust anchor)
    └── signe ──> client1_cert.pem (contient pubKey de Client 1)
    └── signe ──> client2_cert.pem (contient pubKey de Client 2)
```

Pour valider `client1_cert.pem`, il suffit d'avoir `ca_cert.pem` : on vérifie que la signature dans `client1_cert.pem` a bien été produite par la CA. On n'a pas besoin que la CA soit en ligne (contrairement à OCSP) — la vérification est **hors ligne et locale**.

### Protocole de handshake 3.6

Le format du message change : `Base64(ecdhPub) | Base64(sig) | Base64(cert_DER)`

Le certificat X.509 (encodé DER) remplace la clé publique ECDSA brute. À la réception :

```java
// 1. Parser le certificat X.509 depuis les octets DER reçus
CertificateFactory cf = CertificateFactory.getInstance("X.509");
X509Certificate otherCert = (X509Certificate) cf.generateCertificate(
    new ByteArrayInputStream(otherCertBytes));
```

`CertificateFactory.getInstance("X.509")` : retourne une factory capable de parser des certificats X.509 depuis un flux d'octets DER. Si les octets ne forment pas un certificat DER valide, `generateCertificate()` lève une `CertificateException`.

```java
// 2. Vérifier la signature de la CA sur le certificat
otherCert.verify(caCert.getPublicKey());
```

`verify(caCert.getPublicKey())` : recalcule la signature du certificat avec la clé publique de la CA et la compare à celle stockée dans le certificat. Si elles correspondent, la CA a bien signé ce certificat — la clé publique qu'il contient est certifiée. Si elles ne correspondent pas (ou si le parseur ne peut pas construire le certificat), une exception est levée.

```java
// 3. Extraire la clé publique ECDSA (maintenant de confiance car certifiée par la CA)
PublicKey otherEcdsaPub = otherCert.getPublicKey();

// 4. Vérifier la signature ECDSA sur la clé ECDH
Signature verifier = Signature.getInstance("SHA256withECDSA");
verifier.initVerify(otherEcdsaPub);
verifier.update(otherEcdhPubBytes);
verifier.verify(otherSig);
```

La chaîne de confiance est complète :
1. On fait confiance à la CA (par configuration préalable)
2. La CA certifie que `otherEcdsaPub` appartient à `CN=Client1`
3. `otherEcdsaPub` certifie que `ecdhPub` a été émis par `CN=Client1`
4. On dérive la clé de session depuis `ecdhPub`

### Démonstration

Le MitM ne possède pas `ca_private.pem`. Il lui est donc impossible de créer un certificat X.509 valide signé par la CA. Il envoie sa clé publique ECDSA brute comme si c'était un certificat. Côté client, le parsing `CertificateFactory.generateCertificate()` échoue immédiatement car les données ne sont pas un certificat DER valide :

```
[ERREUR PKI] Certificat invalide - attaque MitM detectee ! Unable to initialize: Too short
```

La connexion est refusée et les clients déconnectent.

**Condition nécessaire** : tous les participants doivent faire confiance à la même CA et disposer de `ca_cert.pem`. La sécurité repose entièrement sur la protection de `ca_private.pem` — si cette clé est compromise, un attaquant peut émettre des certificats valides pour n'importe quelle identité. C'est pourquoi dans les PKI réelles, la clé privée de la CA racine est stockée hors ligne (HSM, coffre-fort physique).

---

## 8. Étape 3.7 — Attaques résiduelles et Perfect Forward Secrecy

### 3.7.1 — Attaques encore possibles avec PKI

Même avec une PKI complète, deux attaques restent possibles au niveau du **transport** : elles ne cassent pas le chiffrement mais manipulent la livraison des messages.

#### Attaque par rejeu (Replay Attack)

**Scénario** : Client 1 envoie "Viens à 20h", puis "Finalement 21h". Le `ServerInterceptor` sauvegarde le premier message chiffré lors de sa première transmission. Lors du deuxième message, il le remplace par l'ancien.

```
Client 1               ServerInterceptor             Client 2
    |-- msg[0]="Viens 20h" -->|                          |
    |                          |-- msg[0] sauvegardé -->  |  (Client 2 reçoit "Viens 20h" ✓)
    |-- msg[1]="Finalement 21h"|                          |
    |                          |-- REJEU msg[0] ------->  |  (Client 2 reçoit "Viens 20h" à nouveau !)
```

**Pourquoi AES-GCM ne détecte pas** : le message rejoué est un message **authentique et non modifié** — son tag GCM est valide. AES-GCM garantit uniquement qu'un message n'a pas été altéré en transit. Il ne peut pas savoir si un message a déjà été vu auparavant.

```java
// ServerInterceptor 3.7.1 — sauvegarde et rejoue
if (fromClient1 && c1MsgCount == 1) {
    savedC1Msg = message;  // sauvegarde le 1er message de C1
}
if (fromClient1 && c1MsgCount == 2) {
    return savedC1Msg;     // remplace le 2e message par le 1er
}
```

#### Attaque par suppression (Drop Attack)

Le `ServerInterceptor` peut retourner `null` depuis `onMessageRelay()`, ce qui empêche la transmission du message. Client 2 ne reçoit rien. Sans numérotation, Client 2 ne peut pas distinguer :
- Une panne réseau légitime
- Une suppression intentionnelle par un attaquant

Si l'attaquant supprime `msg[2]` et laisse passer `msg[3]`, Client 2 reçoit `msg[3]` sans savoir qu'il a manqué `msg[2]`.

### 3.7.2 — Protection par numéros de séquence

Chaque message est préfixé par un compteur 32 bits **avant** chiffrement. Puisque ce compteur fait partie du payload chiffré et authentifié par GCM, il ne peut pas être modifié sans invalider le tag.

#### Encodage du compteur

```java
// Envoi — préfixage big-endian 32 bits
byte[] payload = new byte[4 + msgBytes.length];
payload[0] = (byte)(sendCounter >> 24);
payload[1] = (byte)(sendCounter >> 16);
payload[2] = (byte)(sendCounter >> 8);
payload[3] = (byte)(sendCounter);
System.arraycopy(msgBytes, 0, payload, 4, msgBytes.length);
sendCounter++;
// Le payload est ensuite chiffré en AES-GCM
```

**Pourquoi big-endian ?** Convention standard réseau (Network Byte Order, définie par la RFC 791) : l'octet de poids fort est envoyé en premier. Cela permet à n'importe quelle implémentation de lire un entier multi-octets de manière non ambiguë.

**Pourquoi 32 bits ?** Un compteur 32 bits peut compter jusqu'à ~4 milliards de messages par session, largement suffisant. Pour des sessions longue durée en production, on utiliserait 64 bits.

#### Vérification à la réception

```java
// Réception — extraction et vérification
int seqNum = ((payload[0] & 0xFF) << 24) | ((payload[1] & 0xFF) << 16)
           | ((payload[2] & 0xFF) << 8)  |  (payload[3] & 0xFF);
if (seqNum != recvCounter) {
    return "[REPLAY DETECTE ! message rejete - seq attendu=" + recvCounter + " recu=" + seqNum + "]";
}
recvCounter++;
String message = new String(payload, 4, payload.length - 4, StandardCharsets.UTF_8);
```

L'opération `& 0xFF` est nécessaire car les `byte` Java sont **signés** (de -128 à 127). Si `payload[0] = (byte)0xFF = -1`, alors `(int)payload[0] = -1`, mais `(-1 & 0xFF) = 255`. Sans ce masque, la reconstruction de l'entier serait incorrecte pour des octets > 127.

#### Compteurs indépendants par direction

Chaque client maintient deux compteurs indépendants :
- `sendCounter` : incrémenté à chaque message envoyé
- `recvCounter` : valeur attendue du prochain message reçu

Les flux C1→C2 et C2→C1 sont numérotés séparément (chaque client part de 0 pour ses envois). Cela évite toute confusion entre les messages des deux sens.

#### Pourquoi ce mécanisme détecte les deux attaques

- **Rejeu** : le vieux message `msg[0]` contient `seq=0`. Quand il est rejoué à la place de `msg[1]`, le client attendait `seq=1`. Décalage détecté → message rejeté.
- **Suppression** : si `msg[1]` (seq=1) est supprimé, le message suivant `msg[2]` (seq=2) arrive alors que le client attend seq=1. Saut détecté → message rejeté.

**Sécurité** : le numéro de séquence est **à l'intérieur** du chiffrement GCM. Un attaquant ne peut pas modifier le compteur sans invalider le tag d'authentification. Il ne peut pas non plus forger un nouveau message avec seq=1 sans connaître la clé de session (confidentialité AES-GCM).

### 3.7.3 — Perfect Forward Secrecy (PFS)

**Scénario** : un attaquant (services de renseignement, FAI malveillant...) enregistre **tout le trafic chiffré** entre les clients depuis le début. Quelques mois plus tard, il compromet les fichiers `client1_private.pem` et `client2_private.pem`.

**Question** : peut-il maintenant déchiffrer les conversations passées ?

**Réponse : non.** Voici pourquoi.

**Ce que les clés privées ECDSA permettent** :
- Signer des messages (comme si on était Client 1 ou Client 2)
- Usurper l'identité pour de futures sessions

**Ce que les clés privées ECDSA ne permettent pas** :
- Recalculer le secret ECDH des sessions passées

Le secret ECDH est calculé ainsi : `sharedSecret = ECDH(ecdhPrivEphemeral_1, ecdhPubEphemeral_2)`. Pour recalculer ce secret, il faudrait connaître `ecdhPrivEphemeral_1` ou `ecdhPrivEphemeral_2` — les clés ECDH **éphémères** générées en mémoire lors du handshake.

```java
KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
kpg.initialize(new ECGenParameterSpec("secp256r1"));
KeyPair ecdhKeyPair = kpg.generateKeyPair(); // uniquement en mémoire RAM
```

Ces clés éphémères n'ont jamais été sauvegardées. Elles ont existé en mémoire RAM pendant quelques millisecondes lors du handshake, puis ont été collectées par le garbage collector. **Elles sont irrécupérables.**

**Cette propriété s'appelle la Perfect Forward Secrecy (PFS)** : la compromission future des clés long terme ne rétroactivement pas compromet la confidentialité des sessions passées. Elle est garantie uniquement parce que les clés de session sont **éphémères et non persistées**. C'est l'un des avantages fondamentaux de l'ECDH éphémère — et pourquoi les protocoles modernes comme TLS 1.3 exigent des clés éphémères.

---

## 9. Bilan et conclusion

### Progression de la sécurité

| Étape | Mécanisme | Confidentialité | Intégrité | Authentification | Anti-rejeu |
|-------|-----------|:-:|:-:|:-:|:-:|
| 3.1 | ROT13 | ✗ | ✗ | ✗ | ✗ |
| 3.2 | AES/CTR + SHA-256 | ✓ | ✗ | ✗ | ✗ |
| 3.3 | AES-GCM | ✓ | ✓ | ✗ | ✗ |
| 3.4 | ECDH éphémère | ✓ | ✓ | ✗ | ✗ |
| 3.5 | + ECDSA signatures | ✓ | ✓ | Partielle | ✗ |
| 3.6 | + PKI / CA | ✓ | ✓ | ✓ | ✗ |
| 3.7 | + Numéros de séquence | ✓ | ✓ | ✓ | ✓ |

### Primitives cryptographiques utilisées

| Primitive | Algorithme | Rôle |
|-----------|-----------|------|
| Chiffrement symétrique | AES-128/GCM | Confidentialité + intégrité des messages |
| Échange de clés | ECDH (secp256r1) | Établissement de la clé de session |
| Signature numérique | SHA256withECDSA | Authentification des clés ECDH |
| Certificats | X.509 | Liaison identité ↔ clé publique |
| Hachage | SHA-256 | Dérivation de clé depuis ECDH |
| Aléatoire | SecureRandom | Génération d'IV et de clés |
| Encodage | Base64 | Transport des données binaires sur TCP texte |

### Toutes les API Java utilisées

- `KeyPairGenerator` : génération de paires de clés EC (ECDH et ECDSA)
- `KeyAgreement` : calcul du secret ECDH partagé
- `Signature` : signature et vérification SHA256withECDSA
- `Cipher` : chiffrement/déchiffrement AES-GCM
- `MessageDigest` : hachage SHA-256 pour dérivation de clé
- `CertificateFactory` : parsing de certificats X.509 DER
- `X509Certificate` : manipulation et vérification de certificats
- `SecretKeySpec` : construction d'une clé AES à partir de bytes
- `GCMParameterSpec` : paramètres AES-GCM (taille du tag, IV)
- `ECGenParameterSpec` : spécification de la courbe elliptique
- `PKCS8EncodedKeySpec` / `X509EncodedKeySpec` : chargement de clés depuis PEM
- `KeyFactory` : reconstruction de clés à partir de specs
- `SecureRandom` : génération cryptographiquement sûre d'IV
- `Base64` : encodage/décodage pour transport réseau
