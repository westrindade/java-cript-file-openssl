package com.example.testCriptoFile.testCriptFile;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;

public class AESKeyGenerator {

    public static String generateRandomAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256, new SecureRandom());
        SecretKey secretKey = keyGen.generateKey();
        return bytesToHex(secretKey.getEncoded());
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static void main(String[] args) {
        try {
            String randomKeyHex = generateRandomAESKey();

            System.out.println("Chave AES-256 gerada: " + randomKeyHex);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
