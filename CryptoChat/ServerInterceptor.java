
/*public class ServerInterceptor {
    public ServerInterceptor() {
        System.out.println("[Server] Honest relay mode");
    }

    public String onMessageRelay(String message, int fromClient, int toClient) {
        // Honest relay - no modification
		System.out.println("Relaying from " + fromClient + " to client " + toClient + " : " + message);
        return message;
    }
}*/


//Implémentation de l'attaque 3.1.2
/* 
public class ServerInterceptor {

    public ServerInterceptor() {
        System.out.println("[Server] MITM mode (ROT13 attack)");
    }

    public String onMessageRelay(String message, int fromClient, int toClient) {

        // Message intercepté
        System.out.println("Intercepted message (encrypted): " + message);

        // Déchiffrement ROT13
        String decrypted = rot13(message);

        // Message en clair
        System.out.println("Decrypted message (cleartext): " + decrypted);

        // Relay du message original
        return message;
    }

    private String rot13(String input) {
        StringBuilder result = new StringBuilder();

        for (char c : input.toCharArray()) {
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
*/


//Implementation de la partie 3.2.4

import java.util.Base64;

public class ServerInterceptor {

    public ServerInterceptor() {
        System.out.println("[Server] MITM modification mode");
    }

    public String onMessageRelay(String message, int fromClient, int toClient) {
        try {
            System.out.println("[MITM] Message intercepté (Base64) : " + message);

            byte[] all = Base64.getDecoder().decode(message);

            // IV = 16 octets, puis ciphertext
            // On modifie un octet plus loin pour éviter de casser le padding final
            if (all.length > 40) {
                all[30] ^= 0x01;
                System.out.println("[MITM] Un bit a été modifié à l'index 30.");
            }

            return Base64.getEncoder().encodeToString(all);

        } catch (Exception e) {
            System.out.println("[MITM] Erreur : " + e.getMessage());
            return message;
        }
    }
}