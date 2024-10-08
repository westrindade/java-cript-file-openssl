package com.example.testCriptoFile.testCriptFile;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;

public class SimpleAES {

    private static final String ALGORITHM = "AES/ECB/PKCS5Padding";
    private static final int KEY_SIZE = 32;

    public static final int ENCRYPT_MODE = 1;
    public static final int DECRYPT_MODE = 2;

    private static void validateParameters(String inputFile, String outputFile, byte[] key) {
        if (key.length != KEY_SIZE) {
            throw new IllegalArgumentException("A chave deve ter 32 bytes para AES-256.");
        }

        if (inputFile == null || outputFile == null) {
            throw new IllegalArgumentException("Os caminhos dos arquivos de entrada e saída não podem ser nulos.");
        }

        Path inputPath = Paths.get(inputFile);
        if (!Files.exists(inputPath) || !Files.isReadable(inputPath)) {
            throw new IllegalArgumentException("O arquivo de entrada não existe ou não pode ser lido.");
        }

        Path outputPath = Paths.get(outputFile).getParent();
        if (outputPath != null && !Files.exists(outputPath)) {
            throw new IllegalArgumentException("O diretório de saída não existe.");
        }
    }

    private static void crypt(String inputFile, String outputFile, byte[] key, int typeCrypt) throws IllegalArgumentException, InvalidKeyException, IOException {
        try {
            validateParameters(inputFile, outputFile, key);

            Path inputPath = Paths.get(inputFile);
            Path outputPath = Paths.get(outputFile);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            cipher.init(typeCrypt, secretKeySpec);

            byte[] inputBytes = Files.readAllBytes(inputPath);
            byte[] outputBytes = cipher.doFinal(inputBytes);

            Files.write(outputPath, outputBytes);
        } catch (InvalidKeyException e) {
            throw new InvalidKeyException("Erro na chave: " + e.getMessage(), e);
        } catch (IOException e) {
            throw new IOException("Erro ao ler/escrever arquivos: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new RuntimeException("Erro ao realizar a encriptação: " + e.getMessage(), e);
        }
    }

    public static void encrypt(String inputFile, String outputFile, byte[] key) throws Exception {
        crypt(inputFile, outputFile, key, ENCRYPT_MODE);
    }

    public static void decrypt(String inputFile, String outputFile, byte[] key) throws Exception {
        crypt(inputFile, outputFile, key, DECRYPT_MODE);
    }

    public static void main(String[] args) {
        try {
            String keyHex = AESKeyGenerator.generateRandomAESKey(); //chave AES-256

            System.out.println("keyHex["+keyHex+"]");

            byte[] key = AESKeyGenerator.hexStringToByteArray(keyHex); // Converte chave hex para byte array

            // Criptografar
            String nameFile = "TESTE";
            String inputFile = String.format("C:\\Users\\wtrindade\\Downloads\\%s.xlsx", nameFile);
            String outputFile = String.format("C:\\Users\\wtrindade\\Downloads\\%s-encript.aes", nameFile);
            String decriptFile = String.format("C:\\Users\\wtrindade\\Downloads\\%s-decript-java.xlsx", nameFile);
            encrypt(inputFile, outputFile, key);

            // Descriptografar
            decrypt(outputFile, decriptFile, key);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
