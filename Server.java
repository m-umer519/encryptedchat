import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;
import java.util.regex.Pattern;

public class Server {
    private static final int PORT = 5000;
    private static final String CREDS_FILE = "creds.txt";
    private static final int DH_KEY_SIZE = 2048;
    private static final long KEY_EXPIRY_TIME = 5 * 60 * 1000; // 5 minutes in milliseconds
    

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Server started on port " + PORT);
            while (true) {
                Socket clientSocket = serverSocket.accept();
                new ClientHandler(clientSocket).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    static class ClientHandler extends Thread {
        private Socket socket;
        private DataInputStream in;
        private DataOutputStream out;
        private SecretKey sessionKey;
        private long sessionKeyTime;

        public ClientHandler(Socket socket) {
            this.socket = socket;
            try {
                in = new DataInputStream(socket.getInputStream());
                out = new DataOutputStream(socket.getOutputStream());
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        @Override
        public void run() {
            try {
                while (true) {
                    String choice = in.readUTF();
                    if (choice.equals("register")) {
                        handleRegistration();
                    } else if (choice.equals("login")) {
                        handleLogin();
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                try {
                    socket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        private void handleRegistration() {
            try {
                performDHKeyExchange();
                String encryptedData = in.readUTF();
                String decryptedData = decrypt(encryptedData, sessionKey);
                String[] parts = decryptedData.split("\\|");
                String email = parts[0];
                String username = parts[1];
                String password = parts[2];

                if (!isValidEmail(email)) {
                    sendEncryptedMessage("Invalid email format", sessionKey);
                    return;
                }

                if (userExists(username)) {
                    sendEncryptedMessage("Username already exists", sessionKey);
                    return;
                }

                byte[] salt = generateSalt();
                String hashedPassword = hashPassword(password, salt);
                storeCredentials(email, username, hashedPassword, Base64.getEncoder().encodeToString(salt));
                sendEncryptedMessage("Registration successful", sessionKey);
            } catch (IOException e) {
                e.printStackTrace();
                try {
                    sendEncryptedMessage("Registration failed", sessionKey);
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            } catch (Exception e) {
                e.printStackTrace();
                try {
                    sendEncryptedMessage("Registration failed", sessionKey);
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
        }

        private void handleLogin() {
            try {
                performDHKeyExchange();
                String encryptedData = in.readUTF();
                String decryptedData = decrypt(encryptedData, sessionKey);
                String[] parts = decryptedData.split("\\|");
                String username = parts[0];
                String password = parts[1];

                if (verifyCredentials(username, password)) {
                    sendEncryptedMessage("Login successful", sessionKey);
                    handleChat(username);
                } else {
                    sendEncryptedMessage("Login failed", sessionKey);
                }
            } catch (IOException e) {
                e.printStackTrace();
                try {
                    sendEncryptedMessage("Login failed", sessionKey);
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            } catch (Exception e) {
                e.printStackTrace();
                try {
                    sendEncryptedMessage("Login failed", sessionKey);
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
        }

        private void handleChat(String username) throws Exception {
            if (isSessionKeyExpired()) {
                performDHKeyExchange(); // Regenerate key if expired
            }
            String chatKey = username + Base64.getEncoder().encodeToString(sessionKey.getEncoded());
            SecretKey messagingKey = generateAESKey(chatKey);

            System.out.println("Chat session started. Type 'bye' to exit.");

            // Separate thread to read messages from the client
            new Thread(() -> {
                try {
                    while (true) {
                        String encryptedMessage = in.readUTF();
                        String message = decrypt(encryptedMessage, messagingKey);
                        System.out.println("Received from " + username + ": " + message);

                        if (message.equalsIgnoreCase("bye")) {
                            break;
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }).start();

            // Main thread to read messages from the server terminal
            Scanner scanner = new Scanner(System.in);
            while (true) {
                String message = scanner.nextLine();
                sendEncryptedMessage(message, messagingKey);

                if (message.equalsIgnoreCase("bye")) {
                    break;
                }
            }
        }

        private void performDHKeyExchange() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
            keyGen.initialize(DH_KEY_SIZE);
            KeyPair serverPair = keyGen.generateKeyPair();

            byte[] publicKeyBytes = serverPair.getPublic().getEncoded();
            out.writeInt(publicKeyBytes.length);
            out.write(publicKeyBytes);

            int length = in.readInt();
            byte[] clientPublicKeyBytes = new byte[length];
            in.readFully(clientPublicKeyBytes);

            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(clientPublicKeyBytes);
            PublicKey clientPublicKey = keyFactory.generatePublic(x509KeySpec);

            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(serverPair.getPrivate());
            keyAgreement.doPhase(clientPublicKey, true);

            byte[] sharedSecret = keyAgreement.generateSecret();
            sessionKey = generateAESKey(Base64.getEncoder().encodeToString(sharedSecret));
            sessionKeyTime = System.currentTimeMillis(); // Update the key generation time
        }

        private boolean isSessionKeyExpired() {
            return System.currentTimeMillis() - sessionKeyTime > KEY_EXPIRY_TIME;
        }

        private boolean userExists(String username) {
            try (BufferedReader reader = new BufferedReader(new FileReader(CREDS_FILE))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.split("\\|");
                    if (parts[1].equals(username)) {
                        return true;
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
            return false;
        }

        private void storeCredentials(String email, String username, String hashedPassword, String salt) throws IOException {
            try (FileWriter writer = new FileWriter(CREDS_FILE, true)) {
                writer.write(email + "|" + username + "|" + hashedPassword + "|" + salt + "\n");
            }
        }

        private boolean verifyCredentials(String username, String password) {
            try (BufferedReader reader = new BufferedReader(new FileReader(CREDS_FILE))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.split("\\|");
                    if (parts[1].equals(username)) {
                        String storedHash = parts[2];
                        byte[] salt = Base64.getDecoder().decode(parts[3]);
                        String hashedPassword = hashPassword(password, salt);
                        return storedHash.equals(hashedPassword);
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
            return false;
        }

        private byte[] generateSalt() {
            byte[] salt = new byte[32];
            new SecureRandom().nextBytes(salt);
            return salt;
        }

        private String hashPassword(String password, byte[] salt) {
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(salt);
                byte[] hashedPassword = md.digest(password.getBytes(StandardCharsets.UTF_8));
                return Base64.getEncoder().encodeToString(hashedPassword);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
                return null;
            }
        }

        private void sendEncryptedMessage(String message, SecretKey key) throws Exception {
            String encrypted = encrypt(message, key);
            out.writeUTF(encrypted);
        }

        private String encrypt(String message, SecretKey key) throws Exception {
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

        private String decrypt(String encryptedMessage, SecretKey key) throws Exception {
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

        private SecretKey generateAESKey(String seed) throws NoSuchAlgorithmException {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(seed.getBytes(StandardCharsets.UTF_8));
            return new SecretKeySpec(hash, 0, 16, "AES");
        }

        private boolean isValidEmail(String email) {
            String emailPattern = "^[A-Za-z0-9+_.-]+@(.+)$";
            Pattern pattern = Pattern.compile(emailPattern);
            return pattern.matcher(email).matches();
        }
    }
}