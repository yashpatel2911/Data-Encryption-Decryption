package com.team6;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;


// reference: https://www.codejava.net/coding/file-encryption-and-decryption-simple-example

public class ASE_Algorithm
{
	private static final String ALGO_NAME = "AES";
    private static final String TRANSFORMATION_NAME = "AES";
    
	public static void doEncryption (String aesKey, File read_File, File write_File)
            throws Encryption_Decryption_Exception 
	{
        doExecute(Cipher.ENCRYPT_MODE, aesKey, read_File, write_File);
    }
 
    public static void doDecryption (String aesKey, File read_File, File write_File)
            throws Encryption_Decryption_Exception
    {
        doExecute(Cipher.DECRYPT_MODE, aesKey, read_File, write_File);
    }
 
    private static void doExecute(int cipherModenumber, String aesKey, File read_File, 
    		File write_File) throws Encryption_Decryption_Exception
    {
        try 
        {
            Key aesFinalKey = new SecretKeySpec(aesKey.getBytes(), ALGO_NAME);
            Cipher cipher_aes = Cipher.getInstance(TRANSFORMATION_NAME);
            cipher_aes.init(cipherModenumber, aesFinalKey);
             
            FileInputStream readingStream = new FileInputStream(read_File);
            byte[] readingBytes = new byte[(int) read_File.length()];
            readingStream.read(readingBytes);
             
            byte[] writingBytes = cipher_aes.doFinal(readingBytes);
             
            FileOutputStream writingStream = new FileOutputStream(write_File);
            writingStream.write(writingBytes);
             
            readingStream.close();
            writingStream.close();
             
        } 
        catch (NoSuchPaddingException | NoSuchAlgorithmException
                | InvalidKeyException | BadPaddingException
                | IllegalBlockSizeException | IOException e) 
        {
            throw new Encryption_Decryption_Exception("Exception while encrypting or decrypting:", e);
        }
    }
}
