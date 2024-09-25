package com.example.testCriptoFile.testCriptFile;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;

public class OpenSSLCompatibleAES {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding"; // Alterado para CBC
    private static final int SALT_SIZE = 16; // Tamanho do salt
    private static final int IV_SIZE = 16;   // Tamanho do IV para AES CBC
    private static final int KEY_SIZE = 256; // Tamanho da chave para AES
    private static final int ITERATION_COUNT = 65536; // Número de iterações para PBKDF2
    private static final String SALTED_STR = "Salted__"; // Prefixo de arquivo criptografado OpenSSL
    private static final byte[] SALTED_MAGIC = SALTED_STR.getBytes();

    public static byte[] deriveKeyPBKDF2(String password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATION_COUNT, KEY_SIZE);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return factory.generateSecret(spec).getEncoded();
    }

    public static void encryptFile(String inputFile, String outputFile, String password) throws Exception {
        byte[] salt = new byte[SALT_SIZE];
        new SecureRandom().nextBytes(salt);

        byte[] key = deriveKeyPBKDF2(password, salt);

        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);

        byte[] inputBytes = Files.readAllBytes(Paths.get(inputFile));

        byte[] outputBytes = cipher.doFinal(inputBytes);

        byte[] outputFileBytes = new byte[SALTED_MAGIC.length + salt.length + iv.length + outputBytes.length];

        System.arraycopy(SALTED_MAGIC, 0, outputFileBytes, 0, SALTED_MAGIC.length); // Inclui "Salted__"
        System.arraycopy(salt, 0, outputFileBytes, SALTED_MAGIC.length, salt.length); // Inclui o salt
        System.arraycopy(iv, 0, outputFileBytes, SALTED_MAGIC.length + salt.length, iv.length); // Inclui o IV
        System.arraycopy(outputBytes, 0, outputFileBytes, SALTED_MAGIC.length + salt.length + iv.length, outputBytes.length); // Inclui os dados criptografados

        Files.write(Paths.get(outputFile), outputFileBytes);
    }

    public static void decryptFile(String inputFile, String outputFile, String password) throws Exception {
        byte[] inputBytes = Files.readAllBytes(Paths.get(inputFile));

        byte[] magic = Arrays.copyOfRange(inputBytes, 0, SALTED_MAGIC.length);
        if (!Arrays.equals(magic, SALTED_MAGIC)) {
            throw new IllegalArgumentException("Formato de arquivo criptografado inválido.");
        }

        byte[] salt = Arrays.copyOfRange(inputBytes, SALTED_MAGIC.length, SALTED_MAGIC.length + SALT_SIZE);
        byte[] iv = Arrays.copyOfRange(inputBytes, SALTED_MAGIC.length + SALT_SIZE, SALTED_MAGIC.length + SALT_SIZE + IV_SIZE);
        byte[] encryptedData = Arrays.copyOfRange(inputBytes, SALTED_MAGIC.length + SALT_SIZE + IV_SIZE, inputBytes.length);

        byte[] key = deriveKeyPBKDF2(password, salt);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);

        byte[] decryptedBytes = cipher.doFinal(encryptedData);

        Files.write(Paths.get(outputFile), decryptedBytes);

        System.out.println("Chave: " + bytesToHex(key));
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

            // Criptografar
            encryptFile("C:\\Users\\wtrindade\\Downloads\\teste.txt", "C:\\Users\\wtrindade\\Downloads\\teste-encript.aes", password);

            // Descriptografar
            decryptFile("C:\\Users\\wtrindade\\Downloads\\teste-encript.aes", "C:\\Users\\wtrindade\\Downloads\\arquivo_decriptado-java.txt", password);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
