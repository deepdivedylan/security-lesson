package edu.cnm.deepdivecoding.security;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

class Aes256 {
	private SecretKey key;
	private SecretKeyFactory keyFactory;
	private KeySpec keySpec;
	private byte[] salt;

	public Aes256(String password, byte[] newSalt) throws InvalidKeySpecException, NoSuchAlgorithmException {
		this.setSalt(newSalt);
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

	public byte[] getSalt() {
		return(this.salt);
	}

	public void setSalt(byte[] newSalt) {
		this.salt = newSalt;
	}
}
