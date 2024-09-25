package com.example.testCriptoFile.testCriptFile;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class TestCriptoFileApplication {

	public static void main(String[] args) {
		SpringApplication.run(TestCriptoFileApplication.class, args);

		String inputFilePath = "C:\\Users\\wtrindade\\Downloads\\teste.txt";
		String encryptedFilePath = "C:\\Users\\wtrindade\\Downloads\\arquivo_encriptado.aes";
		String decryptedFilePath = "C:\\Users\\wtrindade\\Downloads\\arquivo_decriptado.txt";


	}

}
