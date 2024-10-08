package com.example.testCriptoFile.testCriptFile;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class UnzipFileExample {

    public static void main(String[] args) {
        String zipFilePath = "C:\\Users\\wtrindade\\Downloads\\teste.zip";
        String destDir = "C:\\Users\\wtrindade\\Downloads\\"; // Diretório de destino para extrair os arquivos

        // Criar o diretório de destino, se não existir
        File dir = new File(destDir);
        if (!dir.exists()) dir.mkdirs();

        try {
            // Criando um FileInputStream para o arquivo ZIP
            FileInputStream fis = new FileInputStream(zipFilePath);
            // Criando o ZipInputStream para ler o conteúdo do ZIP
            ZipInputStream zipIn = new ZipInputStream(fis);
            ZipEntry entry = zipIn.getNextEntry(); // Pega a primeira entrada (arquivo ou pasta)

            // Iterar por cada entrada no arquivo ZIP
            while (entry != null) {
                String filePath = destDir + File.separator + entry.getName();

                if (!entry.isDirectory()) {
                    // Se a entrada não for um diretório, extrair o arquivo
                    extractFile(zipIn, filePath);
                } else {
                    // Se for um diretório, criar o diretório
                    File dirEntry = new File(filePath);
                    dirEntry.mkdirs();
                }

                // Avançar para a próxima entrada
                zipIn.closeEntry();
                entry = zipIn.getNextEntry();
            }

            zipIn.close();
            fis.close();

            System.out.println("Arquivo extraído com sucesso!");

        } catch (IOException e) {
            System.out.println("Ocorreu um erro ao extrair o arquivo ZIP.");
            e.printStackTrace();
        }
    }

    // Método para extrair o arquivo
    private static void extractFile(ZipInputStream zipIn, String filePath) throws IOException {
        // Criando um FileOutputStream para o arquivo extraído
        FileOutputStream fos = new FileOutputStream(filePath);
        byte[] bytesIn = new byte[1024];
        int read;
        while ((read = zipIn.read(bytesIn)) != -1) {
            fos.write(bytesIn, 0, read);
        }
        fos.close();
    }
}
