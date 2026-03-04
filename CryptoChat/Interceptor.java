import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Interceptor {

    //Changement effectuer pour la 3.2.1
    private String password;
    public Interceptor(String password) {
        //Ca aussi je vais le rajouter

        this.password = password;
        
    }

    public void onHandshake(BufferedReader input, PrintWriter output) throws IOException {
        try {
            System.out.println("[Interceptor] Starting handshake");

            

            System.out.println("[Interceptor] Handshake complete!");
        } catch (Exception e) {
            throw new IOException("Handshake failed", e);
        }
    }


    //partie pour la question 3.2.2

    /**
 * Dérive une clé symétrique AES à partir du mot de passe de l'utilisateur.
 *
 * Principe :
 * 1. On applique la fonction de hachage SHA-256 sur le mot de passe.
 * 2. SHA-256 produit un hash de 256 bits (32 octets).
 * 3. Pour AES-128, on a besoin d'une clé de 128 bits (16 octets).
 * 4. On prend donc les 16 premiers octets du hash.
 * 5. Ces 16 octets servent à construire une clé AES utilisable par Cipher.
 */

    private SecretKey deriveAesKeyFromPassword() throws Exception {

    // Création d'un objet MessageDigest utilisant l'algorithme de hachage SHA-256
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

    // Conversion du mot de passe en tableau de bytes (UTF-8) puis calcul du hash SHA-256
        byte[] hash = sha256.digest(password.getBytes(StandardCharsets.UTF_8));

    // AES-128 nécessite une clé de 128 bits = 16 octets
    // On extrait donc les 16 premiers octets du hash
        byte[] keyBytes = Arrays.copyOf(hash, 16);

    // Création de la clé AES à partir du tableau de bytes
        return new SecretKeySpec(keyBytes, "AES");
    }

    public String beforeSend(String plainText) {
        try {
           System.out.println("[Interceptor] Encrypting message: " + plainText);
			return rot13(plainText);
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    //Donc là c'est l'ancienne version 
    // toujours pour la question 3.2.2
    /*public String afterReceive(String encryptedText) {
        try {
            System.out.println("[Interceptor] Decrypting message...");
			return rot13(encryptedText);
        } catch (Exception e) {
            return "[Decryption failed: " + e.getMessage() + "]";
        }
    }*/

	


    public String afterReceive(String encryptedText) {
    try {
        // Affichage dans la console pour indiquer que le message est en cours de déchiffrement
        System.out.println("[Interceptor] Decrypting message...");

        // Recréation de la clé AES à partir du mot de passe
        SecretKey key = deriveAesKeyFromPassword();

        // Décodage Base64 pour récupérer les données binaires
        byte[] all = Base64.getDecoder().decode(encryptedText);

        // Vérification minimale de la taille du message
        // Il doit contenir au moins 16 octets d'IV + 1 octet de ciphertext
        if (all.length < 17) {
            return "[Decryption failed: invalid message length]";
        }

        // Séparation des données reçues :
        // les 16 premiers octets correspondent à l'IV
        byte[] iv = Arrays.copyOfRange(all, 0, 16);

        // le reste correspond au message chiffré
        byte[] ct = Arrays.copyOfRange(all, 16, all.length);

        // Création de l'objet Cipher avec AES en mode CBC et padding PKCS5
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        // Initialisation du cipher en mode déchiffrement avec la clé et l'IV
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        // Déchiffrement du ciphertext
        byte[] pt = cipher.doFinal(ct);

        // Conversion du texte déchiffré en String lisible
        return new String(pt, StandardCharsets.UTF_8);

    } catch (Exception e) {
        // En cas d'erreur (clé incorrecte, message modifié, padding invalide, etc.)
        // on retourne un message d'erreur
        return "[Decryption failed: " + e.getMessage() + "]";
    }
}

	 /**
     * ROT13 encoding/decoding (Caesar cipher with shift of 13)
     * This is NOT secure and is only for initial demonstration.
     * You will replace this with proper cryptographic algorithms.
     *
     * @param text The text to encode/decode
     * @return The ROT13 transformed text
     */
    private String rot13(String text) {
        StringBuilder result = new StringBuilder();
        for (char c : text.toCharArray()) {
            if (c >= 'a' && c <= 'z') {
                result.append((char) ((c - 'a' + 13) % 26 + 'a'));
            } else if (c >= 'A' && c <= 'Z') {
                result.append((char) ((c - 'A' + 13) % 26 + 'A'));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }
}
