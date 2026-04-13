# Messagerie Instantanée Sécurisée

> Projet de cryptographie appliquée — ISEN 4 · Avril 2026

Application de messagerie instantanée en Java implémentant progressivement des mécanismes de sécurité modernes : chiffrement symétrique, échange de clés, signatures numériques, PKI et protection contre les attaques résiduelles.

---

## Architecture

```
CryptoChat/
├── Client.java             # Application cliente (TCP + threads)
├── Server.java             # Serveur de relais TCP (port 8888)
├── Interceptor.java        # Module cryptographique côté client
├── ServerInterceptor.java  # Simulation d'attaque côté serveur (MitM)
├── start.bat               # Script de lancement (Windows)
├── ca_cert.pem             # Certificat de l'autorité de certification
├── client1_cert.pem        # Certificat X.509 de Client 1
├── client1_private.pem     # Clé privée ECDSA de Client 1
├── client2_cert.pem        # Certificat X.509 de Client 2
└── client2_private.pem     # Clé privée ECDSA de Client 2
```

Les deux clients ne communiquent jamais directement — tous les messages transitent par le serveur, ce qui permet de simuler des attaques en modifiant uniquement `ServerInterceptor.java`.

---

## Prérequis

- **Java 11+** (les APIs `javax.crypto`, `java.security.cert` sont utilisées)
- **OpenSSL** (pour régénérer les certificats si besoin)  
  → Windows : `winget install ShiningLight.OpenSSL.Light`

Aucune dépendance externe — uniquement la bibliothèque standard Java.

---

## Lancement

```bat
cd CryptoChat
start.bat
```

Trois fenêtres s'ouvrent : le serveur, Client 1 et Client 2. Une fois les deux clients connectés, le handshake cryptographique s'effectue automatiquement, puis les clients peuvent échanger des messages.

### Compilation manuelle

```bash
cd CryptoChat
javac Server.java ServerInterceptor.java Client.java Interceptor.java
```

---

## Étapes de sécurisation

| Étape | Mécanisme | Confidentialité | Intégrité | Authentification | Anti-rejeu |
|-------|-----------|:-:|:-:|:-:|:-:|
| 3.1 | ROT13 | ✗ | ✗ | ✗ | ✗ |
| 3.2 | AES/CTR + SHA-256 | ✓ | ✗ | ✗ | ✗ |
| 3.3 | AES-GCM (AEAD) | ✓ | ✓ | ✗ | ✗ |
| 3.4 | ECDH éphémère | ✓ | ✓ | ✗ | ✗ |
| 3.5 | + ECDSA (sans PKI) | ✓ | ✓ | Partielle | ✗ |
| 3.6 | + PKI / CA (X.509) | ✓ | ✓ | ✓ | ✗ |
| 3.7 | + Numéros de séquence | ✓ | ✓ | ✓ | ✓ |

### Résumé des attaques démontrées

| Attaque | Étape démontrée | Protection apportée |
|---------|----------------|---------------------|
| Lecture passive | 3.1 | → AES (3.2) |
| Bit-flip (malléabilité) | 3.2 | → AES-GCM (3.3) |
| Man-in-the-Middle ECDH | 3.4 | → ECDSA (3.5) |
| MitM avec fausse identité | 3.5 | → PKI/CA (3.6) |
| Rejeu de message | 3.7.1 | → Numéros de séquence (3.7.2) |
| Suppression de message | 3.7.1 | → Numéros de séquence (3.7.2) |

---

## Primitives cryptographiques

| Rôle | Algorithme | Paramètres |
|------|-----------|-----------|
| Chiffrement symétrique | AES-GCM | 128 bits, tag 128 bits, IV 12 octets |
| Échange de clés | ECDH | secp256r1 (P-256) |
| Signature numérique | ECDSA | SHA256withECDSA, secp256r1 |
| Certificats | X.509 | Signé par CA auto-gérée |
| Dérivation de clé | SHA-256 | 16 premiers octets → AES-128 |
| Aléatoire | SecureRandom | IV par message |
| Encodage | Base64 | Transport sur TCP texte |

---

## Régénérer les certificats

```bash
OPENSSL="C:\Program Files\OpenSSL-Win64\bin\openssl.exe"

# CA
$OPENSSL genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca_private.pem
$OPENSSL req -new -x509 -key ca_private.pem -out ca_cert.pem -days 365 -subj "/CN=CryptoChat CA"

# Client 1
$OPENSSL genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out client1_private.pem
$OPENSSL req -new -key client1_private.pem -out client1_csr.pem -subj "/CN=Client1"
$OPENSSL x509 -req -in client1_csr.pem -CA ca_cert.pem -CAkey ca_private.pem -CAcreateserial -out client1_cert.pem -days 365

# Client 2
$OPENSSL genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out client2_private.pem
$OPENSSL req -new -key client2_private.pem -out client2_csr.pem -subj "/CN=Client2"
$OPENSSL x509 -req -in client2_csr.pem -CA ca_cert.pem -CAkey ca_private.pem -CAcreateserial -out client2_cert.pem -days 365
```

---

## Perfect Forward Secrecy

Les clés ECDH éphémères sont générées en RAM au moment du handshake et ne sont jamais sauvegardées. La compromission ultérieure des clés ECDSA long terme (`client1_private.pem`, `client2_private.pem`) ne permet **pas** de déchiffrer les sessions passées — le secret ECDH ayant été dérivé depuis des clés désormais irrécupérables.

