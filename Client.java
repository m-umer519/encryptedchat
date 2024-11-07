import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.util.Scanner;
import java.util.regex.Pattern;

public class Client {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 5000;
    private static Socket socket;
    private static DataInputStream in;
    private static DataOutputStream out;
    private static SecretKey sessionKey;
    private static long sessionKeyTime;
    private static final int DH_KEY_SIZE = 2048;
    private static final long KEY_EXPIRY_TIME = 5 * 60 * 1000; // 5 minutes
    private static final Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) {
        try {
            socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
            in = new DataInputStream(socket.getInputStream());
            out = new DataOutputStream(socket.getOutputStream());

            while (true) {
                System.out.println("\n1. Register");
                System.out.println("2. Login");
                System.out.println("3. Exit");
                System.out.print("Choose an option: ");

                String choice = scanner.nextLine();

                switch (choice) {
                    case "1":
                        out.writeUTF("register");
                        register();
                        break;
                    case "2":
                        out.writeUTF("login");
                        login();
                        break;
                    case "3":
                        socket.close();
                        System.exit(0);
                        break;
                    default:
                        System.out.println("Invalid choice. Please try again.");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void register() {
        try {
            performDHKeyExchange();

            String email = getValidEmail();
            System.out.print("Enter username: ");
            String username = scanner.nextLine();
            String password = getSecurePassword();

            String registrationData = email + "|" + username + "|" + password;
            String encryptedData = encrypt(registrationData, sessionKey);
            out.writeUTF(encryptedData);

            String response = decrypt(in.readUTF(), sessionKey);
            System.out.println("\nServer response: " + response);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void login() {
        try {
            performDHKeyExchange();

            System.out.print("Enter username: ");
            String username = scanner.nextLine();
            System.out.print("Enter password: ");
            String password = getSecurePassword();

            String loginData = username + "|" + password;
            String encryptedData = encrypt(loginData, sessionKey);
            out.writeUTF(encryptedData);

            String response = decrypt(in.readUTF(), sessionKey);
            System.out.println("\nServer response: " + response);

            if (response.equals("Login successful")) {
                startChat(username);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void startChat(String username) {
        try {
            if (isSessionKeyExpired()) {
                performDHKeyExchange();
            }
            String chatKey = username + Base64.getEncoder().encodeToString(sessionKey.getEncoded());
            SecretKey messagingKey = generateAESKey(chatKey);

            System.out.println("\nChat session started. Type 'bye' to exit.");

            // Thread for receiving messages
            new Thread(() -> {
                try {
                    while (true) {
                        String encryptedResponse = in.readUTF();
                        String response = decrypt(encryptedResponse, messagingKey);
                        System.out.println("\nServer: " + response);

                        if (response.equalsIgnoreCase("bye")) {
                            break;
                        }
                    }
                } catch (Exception e) {
                    if (!socket.isClosed()) {
                        e.printStackTrace();
                    }
                }
            }).start();

            // Main thread for sending messages
            while (true) {
                String message = scanner.nextLine();
                String encryptedMessage = encrypt(message, messagingKey);
                out.writeUTF(encryptedMessage);

                if (message.equalsIgnoreCase("bye")) {
                    break;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void performDHKeyExchange() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        keyGen.initialize(DH_KEY_SIZE);
        KeyPair clientPair = keyGen.generateKeyPair();

        int length = in.readInt();
        byte[] serverPublicKeyBytes = new byte[length];
        in.readFully(serverPublicKeyBytes);

        byte[] publicKeyBytes = clientPair.getPublic().getEncoded();
        out.writeInt(publicKeyBytes.length);
        out.write(publicKeyBytes);

        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(serverPublicKeyBytes);
        PublicKey serverPublicKey = keyFactory.generatePublic(x509KeySpec);

        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(clientPair.getPrivate());
        keyAgreement.doPhase(serverPublicKey, true);

        byte[] sharedSecret = keyAgreement.generateSecret();
        sessionKey = generateAESKey(Base64.getEncoder().encodeToString(sharedSecret));
        sessionKeyTime = System.currentTimeMillis(); // Update the key generation time
    }

    private static boolean isSessionKeyExpired() {
        return System.currentTimeMillis() - sessionKeyTime > KEY_EXPIRY_TIME;
    }

    private static String getValidEmail() {
        String emailPattern = "^[A-Za-z0-9+_.-]+@(.+)$";
        Pattern pattern = Pattern.compile(emailPattern);

        while (true) {
            System.out.print("Enter email address: ");
            String email = scanner.nextLine();

            if (pattern.matcher(email).matches()) {
                return email;
            }
            System.out.println("Invalid email format. Please try again.");
        }
    }

    private static String getSecurePassword() {
        while (true) {
            System.out.print("Enter password (minimum 8 characters, must include uppercase, lowercase, number): ");
            String password = scanner.nextLine();

            if (isPasswordSecure(password)) {
                return password;
            }
            System.out.println("Password does not meet security requirements. Please try again.");
        }
    }

    private static boolean isPasswordSecure(String password) {
        return password.length() >= 8 && 
               password.chars().anyMatch(Character::isUpperCase) &&
               password.chars().anyMatch(Character::isLowerCase) &&
               password.chars().anyMatch(Character::isDigit);
    }

    private static String encrypt(String message, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] encrypted = cipher.doFinal(message.getBytes());
        byte[] combined = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);
        return Base64.getEncoder().encodeToString(combined);
    }

    private static String decrypt(String encryptedMessage, SecretKey key) throws Exception {
        byte[] combined = Base64.getDecoder().decode(encryptedMessage);
        byte[] iv = new byte[16];
        byte[] encrypted = new byte[combined.length - 16];
        System.arraycopy(combined, 0, iv, 0, 16);
        System.arraycopy(combined, 16, encrypted, 0, encrypted.length);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted);
    }

    private static SecretKey generateAESKey(String seed) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(seed.getBytes(StandardCharsets.UTF_8));
        return new SecretKeySpec(hash, 0, 16, "AES");
    }
}