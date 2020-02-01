package com.team6;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

//reference: https://mkyong.com/java/java-asymmetric-cryptography-example/

public class RSA_Algorithm
{
	
	private Cipher rsaCipher;
	
	public RSA_Algorithm() throws NoSuchAlgorithmException, NoSuchPaddingException{
		this.rsaCipher = Cipher.getInstance("RSA");
	}
	
	//https://docs.oracle.com/javase/8/docs/api/java/security/spec/PKCS8EncodedKeySpec.html
	public PrivateKey getPrivateKey(String fileLocation) throws Exception 
	{
		byte[] privatekeyBytes = Files.readAllBytes(new File(fileLocation).toPath());
		PKCS8EncodedKeySpec codecSpec = new PKCS8EncodedKeySpec(privatekeyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return keyFactory.generatePrivate(codecSpec);
	}
	//https://docs.oracle.com/javase/8/docs/api/java/security/spec/X509EncodedKeySpec.html
	public PublicKey getPublicKey(String fileLocation) throws Exception 
	{
		byte[] publickeyBytes = Files.readAllBytes(new File(fileLocation).toPath());
		X509EncodedKeySpec codecSpec = new X509EncodedKeySpec(publickeyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return keyFactory.generatePublic(codecSpec);
	}
	
	public void encryptASEKey(byte[] inputKEY, File outputFile, PrivateKey privatekey) throws IOException, GeneralSecurityException
	{
		this.rsaCipher.init(Cipher.ENCRYPT_MODE, privatekey);
		writeToFile(outputFile, this.rsaCipher.doFinal(inputKEY));
    }
	
	public void decryptASEKey(byte[] inputKEY, File outputFile, PublicKey publickey) throws IOException, GeneralSecurityException 
	{
		this.rsaCipher.init(Cipher.DECRYPT_MODE, publickey);
		writeToFile(outputFile, this.rsaCipher.doFinal(inputKEY));
    }
	
	private void writeToFile(File outputFile, byte[] bytetoWrite) throws IllegalBlockSizeException, BadPaddingException, IOException
	{
		FileOutputStream writingFile = new FileOutputStream(outputFile);
		writingFile.write(bytetoWrite);
		writingFile.flush();
		writingFile.close();
	}
	
	public byte[] filetoBytes(File file) throws IOException
	{
		FileInputStream readFile = new FileInputStream(file);
		byte[] file_Bytes = new byte[(int) file.length()];
		readFile.read(file_Bytes);
		readFile.close();
		return file_Bytes;
	}
}
