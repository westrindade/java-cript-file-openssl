package com.example.testCriptoFile.testCriptFile;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;

public class BouncyCastleAES {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int IV_SIZE = 16; // Tamanho do bloco AES
    private static final int SALT_SIZE = 16; // Tamanho do salt
    private static final int KEY_SIZE = 256; // Tamanho da chave para AES
    private static final int ITERATION_COUNT = 65536; // Número de iterações para PBKDF2

    public static byte[] deriveKey(String password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATION_COUNT, KEY_SIZE);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return factory.generateSecret(spec).getEncoded();
    }

    public static void encryptFile(String inputFile, String outputFile, String password) throws Exception {
        byte[] salt = new byte[SALT_SIZE];
        new SecureRandom().nextBytes(salt);

        byte[] key = deriveKey(password, salt);

        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));

        byte[] inputBytes = Files.readAllBytes(Paths.get(inputFile));

        byte[] outputBytes = cipher.doFinal(inputBytes);

        byte[] outputFileBytes = new byte[salt.length + iv.length + outputBytes.length];

        System.arraycopy(salt, 0, outputFileBytes, 0, salt.length);
        System.arraycopy(iv, 0, outputFileBytes, salt.length, iv.length);
        System.arraycopy(outputBytes, 0, outputFileBytes, salt.length + iv.length, outputBytes.length);

        Files.write(Paths.get(outputFile), outputFileBytes);
    }

    public static void decryptFile(String inputFile, String outputFile, String password) throws Exception {
        byte[] inputBytes = Files.readAllBytes(Paths.get(inputFile));

        byte[] salt = new byte[SALT_SIZE];
        System.arraycopy(inputBytes, 0, salt, 0, SALT_SIZE);

        byte[] iv = new byte[IV_SIZE];
        System.arraycopy(inputBytes, SALT_SIZE, iv, 0, IV_SIZE);

        byte[] encryptedData = new byte[inputBytes.length - SALT_SIZE - IV_SIZE];
        System.arraycopy(inputBytes, SALT_SIZE + IV_SIZE, encryptedData, 0, encryptedData.length);

        byte[] key = deriveKey(password, salt);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));

        byte[] decryptedBytes = cipher.doFinal(encryptedData);

        Files.write(Paths.get(outputFile), decryptedBytes);

        System.out.println("Chave: " + bytesToHex(key));
        System.out.println("IV: " + bytesToHex(iv));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static void main(String[] args) {
        try {
            String password = "senhaSegura12345678910"; // Defina a senha aqui

            encryptFile("C:\\Users\\wtrindade\\Downloads\\teste.txt", "C:\\Users\\wtrindade\\Downloads\\teste-encript.aes", password);

            decryptFile("C:\\Users\\wtrindade\\Downloads\\teste-encript.aes", "C:\\Users\\wtrindade\\Downloads\\arquivo_decriptado-java.txt", password);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
