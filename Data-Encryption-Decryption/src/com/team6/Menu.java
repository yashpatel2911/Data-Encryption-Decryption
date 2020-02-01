package com.team6;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class Menu {

	public static void main(String[] args) throws IOException
			,Encryption_Decryption_Exception, GeneralSecurityException
	{
		KeyGeneration kGeneration = new KeyGeneration();
		
		kGeneration.generateRandomKeyAES();
		
		System.out.println();
		
		kGeneration.generateKeyPair();
		
		kGeneration.encryptAESKey();
		
		File read_File = new File("Data/Insertion_Time.csv");
		File write_File_encrypted = new File("Data/Insertion_Time_Encrypted.csv");
		File write_File_decrypted = new File("Data/Insertion_Time_Decrypted.csv");
		
		ASE_Algorithm.doEncryption(kGeneration.getAESKey(), 
				read_File , write_File_encrypted);
		ASE_Algorithm.doDecryption(kGeneration.getAESKey(),
				write_File_encrypted, write_File_decrypted);
		
		kGeneration.decryptAESKey();
	}

}
