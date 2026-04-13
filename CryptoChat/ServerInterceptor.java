
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


// Implementation de la partie 3.7 : Attaques résiduelles
// Attaque 1 - Rejeu : le serveur remplace le 2ème message de Client 1 par le 1er (seq=0 rejoué)
//   → Client 2 attend seq=1 mais reçoit seq=0 → [REPLAY DETECTE]
// Attaque 2 - Suppression : le 3ème message de Client 1 est supprimé (return null)
//   → Client 2 ne reçoit rien, le compteur se désynchronise

import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class ServerInterceptor {

    private int handshakeCount = 0;
    private int c1MsgCount = 0;       // nombre de messages reçus de Client 1
    private String savedC1Msg = null; // 1er message de Client 1 sauvegardé

    public ServerInterceptor() {
        System.out.println("[Server] Mode attaques residuelles (rejeu + suppression)");
    }

    public synchronized String onMessageRelay(String message, int fromClient, int toClient) {

        // Relayer le handshake normalement
        if (handshakeCount < 2) {
            handshakeCount++;
            System.out.println("[Server] Relaying handshake from Client " + fromClient);
            return message;
        }

        if (fromClient == 1) {
            c1MsgCount++;

            if (c1MsgCount == 1) {
                // 1er message de Client 1 : sauvegarder et relayer normalement
                savedC1Msg = message;
                System.out.println("[Server] 1er message Client 1 sauvegarde (seq=0), relay normal");
                return message;
            }

            if (c1MsgCount == 2) {
                // 2ème message de Client 1 : rejouer le 1er (seq=0) au lieu du 2ème (seq=1)
                System.out.println("[Replay] ATTAQUE REJEU : seq=0 rejoue vers Client 2 (attendu seq=1) !");
                return savedC1Msg;
            }

            if (c1MsgCount == 3) {
                // 3ème message de Client 1 : suppression
                System.out.println("[Suppression] ATTAQUE SUPPRESSION : message de Client 1 supprime !");
                return null;
            }
        }

        System.out.println("[Server -> Client " + toClient + "]: relay normal");
        return message;
    }
}