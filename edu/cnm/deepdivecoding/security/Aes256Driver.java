package edu.cnm.deepdivecoding.security;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;

class Aes256Driver {

	public static void main(String[] main) {
		String ciphertext = new String();
		String plaintext = new String();
		String password = new String();
		String salt = new String();

		try {
			BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in));
			System.out.print("Enter password: ");
			password = stdin.readLine();
			Aes256 aes256 = new Aes256(password);
			salt = aes256.getSalt();
			System.out.println("Salt: " + salt);
			System.out.print("Enter plaintext: ");
			plaintext = stdin.readLine();
			ciphertext = aes256.encrypt(plaintext);
			System.out.println("Ciphertext: " + ciphertext);
		} catch(Exception exception) {
			System.err.println(exception.getClass().getSimpleName() + ": " + exception.getMessage());
			exception.printStackTrace();
		}
	}
}
