import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.*;

public class Interceptor {

    // Clé de session dérivée lors du handshake ECDH
    private SecretKey sessionKey;

    // 3.7 : Compteurs de séquence pour détecter les attaques par rejeu
    private int sendCounter = 0;
    private int recvCounter = 0;

    // 3.6 : Clé privée ECDSA + certificat X.509 propre + certificat CA pour vérification
    private PrivateKey ecdsaPrivateKey;
    private X509Certificate ownCert;
    private X509Certificate caCert;

    public Interceptor(String privateKeyPath, String certPath, String caCertPath) {
        try {
            this.ecdsaPrivateKey = loadPrivateKey(privateKeyPath);
            this.ownCert         = loadCertificate(certPath);
            this.caCert          = loadCertificate(caCertPath);
            System.out.println("[Interceptor] Certificat chargé : " + ownCert.getSubjectX500Principal().getName());
            System.out.println("[Interceptor] CA : " + caCert.getSubjectX500Principal().getName());
        } catch (Exception e) {
            throw new RuntimeException("Erreur chargement certificats", e);
        }
    }

    // 3.6 : Handshake ECDH avec échange de certificats X.509 signés par la CA
    public void onHandshake(BufferedReader input, PrintWriter output) throws IOException {
        try {
            System.out.println("[Interceptor] Starting ECDH+PKI handshake");

            // Génération paire ECDH éphémère
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair ecdhKeyPair = kpg.generateKeyPair();
            byte[] ecdhPubBytes = ecdhKeyPair.getPublic().getEncoded();

            // Signature de la clé ECDH éphémère avec notre clé ECDSA long terme
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initSign(ecdsaPrivateKey);
            sig.update(ecdhPubBytes);
            byte[] signature = sig.sign();

            // Envoi : ECDH_pub|signature|cert_DER (tout en Base64 séparé par |)
            // Le certificat X.509 contient notre clé publique ECDSA signée par la CA
            String msg = Base64.getEncoder().encodeToString(ecdhPubBytes) + "|"
                       + Base64.getEncoder().encodeToString(signature) + "|"
                       + Base64.getEncoder().encodeToString(ownCert.getEncoded());
            output.println(msg);
            System.out.println("[Interceptor] Clé ECDH signée + certificat envoyés");

            // Réception : ECDH_pub|signature|cert_DER de l'autre client
            String received = input.readLine();
            String[] parts = received.split("\\|");
            byte[] otherEcdhPubBytes = Base64.getDecoder().decode(parts[0]);
            byte[] otherSig         = Base64.getDecoder().decode(parts[1]);
            byte[] otherCertBytes   = Base64.getDecoder().decode(parts[2]);

            // Vérification du certificat X.509 de l'autre client via la clé publique de la CA
            X509Certificate otherCert;
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                otherCert = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(otherCertBytes));
                otherCert.verify(caCert.getPublicKey()); // lève une exception si invalide
            } catch (Exception e) {
                throw new IOException("[ERREUR PKI] Certificat invalide - attaque MitM detectee ! " + e.getMessage());
            }
            System.out.println("[Interceptor] Certificat verifie OK : " + otherCert.getSubjectX500Principal().getName());

            // Vérification de la signature ECDSA sur la clé ECDH
            PublicKey otherEcdsaPub = otherCert.getPublicKey();
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(otherEcdsaPub);
            verifier.update(otherEcdhPubBytes);
            if (!verifier.verify(otherSig)) {
                throw new IOException("[ERREUR] Signature ECDSA invalide !");
            }
            System.out.println("[Interceptor] Signature ECDSA verifiee OK");

            // Dérivation clé de session AES-128 via ECDH + SHA-256
            KeyFactory kf = KeyFactory.getInstance("EC");
            PublicKey otherEcdhPub = kf.generatePublic(new X509EncodedKeySpec(otherEcdhPubBytes));
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(ecdhKeyPair.getPrivate());
            ka.doPhase(otherEcdhPub, true);
            byte[] sharedSecret = ka.generateSecret();

            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sessionKey = new SecretKeySpec(Arrays.copyOf(sha256.digest(sharedSecret), 16), "AES");

            System.out.println("[Interceptor] Cle de session derivee, handshake termine !");
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Handshake failed", e);
        }
    }

    // Chargement clé privée PKCS8 depuis PEM
    private PrivateKey loadPrivateKey(String path) throws Exception {
        String pem = new String(Files.readAllBytes(Paths.get(path)));
        pem = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                 .replace("-----END PRIVATE KEY-----", "")
                 .replaceAll("\\s", "");
        return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(pem)));
    }

    // Chargement certificat X.509 depuis PEM
    private X509Certificate loadCertificate(String path) throws Exception {
        try (InputStream is = Files.newInputStream(Paths.get(path))) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(is);
        }
    }

    // 3.7 : Chiffrement AES-GCM avec numéro de séquence anti-rejeu
    public String beforeSend(String plainText) {
        try {
            System.out.println("[Interceptor] Encrypting message (AES-GCM, seq=" + sendCounter + "): " + plainText);

            byte[] msgBytes = plainText.getBytes(StandardCharsets.UTF_8);

            // Préfixer le message par le numéro de séquence (4 octets big-endian)
            byte[] payload = new byte[4 + msgBytes.length];
            payload[0] = (byte)(sendCounter >> 24);
            payload[1] = (byte)(sendCounter >> 16);
            payload[2] = (byte)(sendCounter >> 8);
            payload[3] = (byte)(sendCounter);
            System.arraycopy(msgBytes, 0, payload, 4, msgBytes.length);
            sendCounter++;

            byte[] iv = new byte[12];
            new SecureRandom().nextBytes(iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, sessionKey, new GCMParameterSpec(128, iv));
            byte[] ct = cipher.doFinal(payload);

            byte[] out = new byte[iv.length + ct.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(ct, 0, out, iv.length, ct.length);

            return Base64.getEncoder().encodeToString(out);

        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    public String afterReceive(String encryptedText) {
        try {
            System.out.println("[Interceptor] Decrypting message (AES-GCM)...");

            byte[] all = Base64.getDecoder().decode(encryptedText);

            if (all.length < 28) {
                return "[Decryption failed: invalid message length]";
            }

            byte[] iv = Arrays.copyOfRange(all, 0, 12);
            byte[] ct = Arrays.copyOfRange(all, 12, all.length);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, sessionKey, new GCMParameterSpec(128, iv));
            byte[] payload = cipher.doFinal(ct);

            // Extraction et vérification du numéro de séquence
            int seqNum = ((payload[0] & 0xFF) << 24) | ((payload[1] & 0xFF) << 16)
                       | ((payload[2] & 0xFF) << 8)  |  (payload[3] & 0xFF);

            if (seqNum != recvCounter) {
                return "[REPLAY DETECTE ! message rejete - seq attendu=" + recvCounter + " recu=" + seqNum + "]";
            }
            recvCounter++;

            return new String(payload, 4, payload.length - 4, StandardCharsets.UTF_8);

        } catch (Exception e) {
            return "[Decryption failed: " + e.getMessage() + "]";
        }
    }

}
