package com.test;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RSA {
	private Key pubKey;
	private Key privKey;

	public RSA() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		SecureRandom random = new SecureRandom();
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");

		generator.initialize(128, random); // 여기에서는 128 bit 키를 생성하였음
		KeyPair pair = generator.generateKeyPair();
		pubKey = pair.getPublic(); // Kb(pub) 공개키
		privKey = pair.getPrivate();// Kb(pri) 개인키
	}

	public String encrypt(String str) throws NoSuchAlgorithmException, 
											NoSuchProviderException, 
											NoSuchPaddingException, 
											InvalidKeyException, 
											IllegalBlockSizeException, 
											BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
		cipher.init(Cipher.ENCRYPT_MODE, pubKey);
		byte[] cipherText = cipher.doFinal(str.getBytes());
		return new String(cipherText);
	}
	
	public String decrypt(String str) throws NoSuchAlgorithmException, 
											NoSuchProviderException, 
											NoSuchPaddingException, 
											InvalidKeyException, 
											IllegalBlockSizeException, 
											BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
		cipher.init(Cipher.DECRYPT_MODE, privKey);
		byte[] plainText = cipher.doFinal(str.getBytes());
		return new String(plainText);
	}
	
	public static void main(String[] args) {
		try {
			RSA rsa = new RSA();
			String encrypt = rsa.encrypt("ABC");
			System.out.println(encrypt);
			String decrypt = rsa.decrypt(encrypt);
			System.out.println(decrypt);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		
	}
}
