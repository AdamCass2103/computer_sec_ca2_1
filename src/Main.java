import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

public class Main {

    private static final String ALGORITHM = "AES";
    private static final String ENCRYPTED_FILE = "ciphertext.txt";
    private static final String DECRYPTED_FILE = "plaintext.txt";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        while (true) {
            System.out.println("\nMENU");
            System.out.println("1. Encrypt a File");
            System.out.println("2. Decrypt a File");
            System.out.println("3. Quit");
            System.out.print("Choose an option: ");

            int choice = scanner.nextInt();
            scanner.nextLine(); // Consume newline

            if (choice == 1) {
                encryptFile(scanner);
            } else if (choice == 2) {
                decryptFile(scanner);
            } else if (choice == 3) {
                System.out.println("Exiting the application. Goodbye!");
                break;
            } else {
                System.out.println("Invalid option. Please try again.");
            }
        }
    }

    private static void encryptFile(Scanner scanner) {
        try {
            System.out.print("Enter the filename to encrypt: ");
            String filename = scanner.nextLine();

            File inputFile = new File(filename);
            if (!inputFile.exists()) {
                System.out.println("File not found. Please check the filename.");
                return;
            }

            SecretKey secretKey = generateKey();
            byte[] fileData = readFile(inputFile);
            byte[] encryptedData = encrypt(fileData, secretKey);

            writeFile(new File(ENCRYPTED_FILE), encryptedData);

            System.out.println("File encrypted successfully.");
            System.out.println("Key (keep this safe!): " + Base64.getEncoder().encodeToString(secretKey.getEncoded()));
            System.out.println("Encrypted data written to: " + ENCRYPTED_FILE);

        } catch (Exception e) {
            System.out.println("Error encrypting file: " + e.getMessage());
        }
    }

    private static void decryptFile(Scanner scanner) {
        try {
            System.out.print("Enter the filename to decrypt: ");
            String filename = scanner.nextLine();
            System.out.print("Enter the key: ");
            String keyString = scanner.nextLine();

            File inputFile = new File(filename);
            if (!inputFile.exists()) {
                System.out.println("File not found. Please check the filename.");
                return;
            }

            SecretKey secretKey = new SecretKeySpec(Base64.getDecoder().decode(keyString), ALGORITHM);
            byte[] fileData = readFile(inputFile);
            byte[] decryptedData = decrypt(fileData, secretKey);

            writeFile(new File(DECRYPTED_FILE), decryptedData);

            System.out.println("File decrypted successfully.");
            System.out.println("Decrypted data written to: " + DECRYPTED_FILE);

        } catch (Exception e) {
            System.out.println("Error decrypting file: " + e.getMessage());
        }
    }

    private static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(256, new SecureRandom());
        return keyGen.generateKey();
    }

    private static byte[] encrypt(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    private static byte[] decrypt(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    private static byte[] readFile(File file) throws IOException {
        return new FileInputStream(file).readAllBytes();
    }

    private static void writeFile(File file, byte[] data) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(data);
        }
    }
}

