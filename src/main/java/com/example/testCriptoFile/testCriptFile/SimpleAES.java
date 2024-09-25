package com.example.testCriptoFile.testCriptFile;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;

public class SimpleAES {

    private static final String ALGORITHM = "AES/ECB/PKCS5Padding";
    private static final int KEY_SIZE = 32;

    public static void encryptFile(String inputFile, String outputFile, byte[] key) throws Exception {
        // Verifica se a chave fornecida tem o tamanho correto
        if (key.length != KEY_SIZE) {
            throw new IllegalArgumentException("A chave deve ter 32 bytes para AES-256.");
        }

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        byte[] inputBytes = Files.readAllBytes(Paths.get(inputFile));

        byte[] outputBytes = cipher.doFinal(inputBytes);

        Files.write(Paths.get(outputFile), outputBytes);
    }

    public static void decryptFile(String inputFile, String outputFile, byte[] key) throws Exception {
        // Verifica se a chave fornecida tem o tamanho correto
        if (key.length != KEY_SIZE) {
            throw new IllegalArgumentException("A chave deve ter 32 bytes para AES-256.");
        }

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

        byte[] inputBytes = Files.readAllBytes(Paths.get(inputFile));

        byte[] decryptedBytes = cipher.doFinal(inputBytes);

        Files.write(Paths.get(outputFile), decryptedBytes);
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public static void main(String[] args) {
        try {
            String keyHex = AESKeyGenerator.generateRandomAESKey(); //chave AES-256

            System.out.println("keyHex["+keyHex+"]");

            byte[] key = hexStringToByteArray(keyHex); // Converte chave hex para byte array

            // Criptografar
            String nameFile = "CNG_20240817_GERAL";
            String inputFile = String.format("C:\\Users\\wtrindade\\Downloads\\%s.txt", nameFile);
            String outputFile = String.format("C:\\Users\\wtrindade\\Downloads\\%s-encript.aes", nameFile);
            String decriptFile = String.format("C:\\Users\\wtrindade\\Downloads\\%s-decript-java.txt", nameFile);
            encryptFile(inputFile, outputFile, key);

            // Descriptografar
            decryptFile(outputFile, decriptFile, key);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
