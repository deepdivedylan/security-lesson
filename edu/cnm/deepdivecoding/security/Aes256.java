package edu.cnm.deepdivecoding.security;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import javax.xml.bind.DatatypeConverter;

class Aes256 {
	private Cipher cipher;
	private SecretKey key;
	private SecretKeyFactory keyFactory;
	private KeySpec keySpec;
	private byte[] salt;

	public Aes256(String password) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException {
		this.cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecureRandom random = new SecureRandom();
		this.salt = new byte[32];
		random.nextBytes(this.salt);
		this.setKey(password);
	}

	public Aes256(String password, String salt) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException {
		this.cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		this.setSalt(salt);
		this.setKey(password);
	}

	public SecretKey getKey() {
		return(this.key);
	}

	public void setKey(String password) throws InvalidKeySpecException, NoSuchAlgorithmException {
		try {
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 262144, 256);
			SecretKey tmpKey = keyFactory.generateSecret(keySpec);
			this.key = new SecretKeySpec(tmpKey.getEncoded(), "AES");
		} catch(InvalidKeySpecException invalidKeySpec) {
			throw(new InvalidKeySpecException(invalidKeySpec.getMessage(), invalidKeySpec));
		} catch(NoSuchAlgorithmException noSuchAlgorithm) {
			throw(new NoSuchAlgorithmException(noSuchAlgorithm.getMessage(), noSuchAlgorithm));
		}
	}

	public String getSalt() {
		return(DatatypeConverter.printHexBinary(this.salt));
	}

	public void setSalt(String salt) {
		this.salt = DatatypeConverter.parseHexBinary(salt);
	}
}
