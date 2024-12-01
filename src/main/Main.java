package main;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.util.Base64;
import java.util.Scanner;

public class Main {

    private static final String ALGORITHM = "AES";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        while (true) {
            System.out.println(" MENU ");
            System.out.println("1. Encrypt a File");
            System.out.println("2. Decrypt a File");
            System.out.println("3. Quit");
            System.out.print("Choose an option: ");

            int choice = 0;
            try {
                choice = Integer.parseInt(scanner.nextLine());
            } catch (NumberFormatException e) {
                System.out.println("Invalid option. Please try again.");
                continue;
            }

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

    public static void encryptFile(Scanner scanner) {
        try {
            System.out.print("Enter the filename to encrypt: ");
            String inputFile = scanner.nextLine().trim();

            File file = new File(inputFile);
            if (!file.exists()) {
                System.out.println("File not found. Please check the path and try again.");
                return;
            }

            // Generate a random AES key
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
            keyGenerator.init(128); // AES-128
            SecretKey secretKey = keyGenerator.generateKey();
            String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());

            // Read the file data
            byte[] fileData = readFile(inputFile);
            byte[] encryptedData = encryptData(fileData, secretKey);

            // Save the encrypted data to a file
            writeFile("ciphertext.txt", encryptedData);

            System.out.println("File encrypted successfully!");
            System.out.println("Encryption key: " + encodedKey);
            System.out.println("Encrypted file saved as: ciphertext.txt");
            System.out.println("Please save the encryption key to decrypt the file later.");

        } catch (Exception e) {
            System.out.println("Error during encryption: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static void decryptFile(Scanner scanner) {
        try {
            System.out.print("Enter the filename to decrypt: ");
            String inputFile = scanner.nextLine().trim();

            File file = new File(inputFile);
            if (!file.exists()) {
                System.out.println("File not found. Please check the path and try again.");
                return;
            }

            System.out.print("Enter the encryption key: ");
            String keyString = scanner.nextLine().trim();

            // Decode the base64 key
            byte[] keyBytes = Base64.getDecoder().decode(keyString);
            SecretKey secretKey = new SecretKeySpec(keyBytes, ALGORITHM);

            byte[] fileData = readFile(inputFile);
            byte[] decryptedData = decryptData(fileData, secretKey);

            // Save the decrypted data to a file
            writeFile("plaintext.txt", decryptedData);

            System.out.println("File decrypted successfully!");
            System.out.println("Decrypted file saved as: plaintext.txt");

        } catch (Exception e) {
            System.out.println("Error during decryption: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static byte[] encryptData(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    private static byte[] decryptData(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    private static byte[] readFile(String filename) throws IOException {
        return java.nio.file.Files.readAllBytes(new File(filename).toPath());
    }

    private static void writeFile(String filename, byte[] data) throws IOException {
        java.nio.file.Files.write(new File(filename).toPath(), data);
    }
}