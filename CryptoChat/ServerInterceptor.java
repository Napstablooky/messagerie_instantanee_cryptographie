
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
