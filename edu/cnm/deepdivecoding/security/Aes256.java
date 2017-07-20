package edu.cnm.deepdivecoding.security;

import java.io.UnsupportedEncodingException;

import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
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
		try {
			this.cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			SecureRandom random = new SecureRandom();
			this.salt = new byte[32];
			random.nextBytes(this.salt);
			this.setKey(password);
		} catch(InvalidKeySpecException invalidKeySpec) {
			throw(new InvalidKeySpecException(invalidKeySpec.getMessage(), invalidKeySpec));
		} catch(NoSuchAlgorithmException noSuchAlgorithm) {
			throw(new NoSuchAlgorithmException(noSuchAlgorithm.getMessage(), noSuchAlgorithm));
		} catch(NoSuchPaddingException noSuchPadding) {
			throw(new NoSuchPaddingException(noSuchPadding.getMessage()));
		}
	}

	public Aes256(String password, String salt) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException {
		try {
			this.cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			this.setSalt(salt);
			this.setKey(password);
		} catch(InvalidKeySpecException invalidKeySpec) {
			throw(new InvalidKeySpecException(invalidKeySpec.getMessage(), invalidKeySpec));
		} catch(NoSuchAlgorithmException noSuchAlgorithm) {
			throw(new NoSuchAlgorithmException(noSuchAlgorithm.getMessage(), noSuchAlgorithm));
		} catch(NoSuchPaddingException noSuchPadding) {
			throw(new NoSuchPaddingException(noSuchPadding.getMessage()));
		}
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

	public String encrypt(String plaintext) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidParameterSpecException, UnsupportedEncodingException {
		try {
			this.cipher.init(Cipher.ENCRYPT_MODE, this.key);
			AlgorithmParameters params = cipher.getParameters();
			byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
			byte[] ciphertext = cipher.doFinal(plaintext.getBytes("UTF-8"));
			return(new String(ciphertext));
		} catch(BadPaddingException badPadding) {
			throw(new BadPaddingException(badPadding.getMessage()));
		} catch(IllegalBlockSizeException illegalBlockSize) {
			throw(new IllegalBlockSizeException(illegalBlockSize.getMessage()));
		} catch(InvalidKeyException invalidKey) {
			throw(new InvalidKeyException(invalidKey.getMessage(), invalidKey));
		} catch(InvalidParameterSpecException invalidParameterSpec) {
			throw(new InvalidParameterSpecException(invalidParameterSpec.getMessage()));
		} catch(UnsupportedEncodingException unsupportedEncoding) {
			throw(new UnsupportedEncodingException(unsupportedEncoding.getMessage()));
		}
	}
}
