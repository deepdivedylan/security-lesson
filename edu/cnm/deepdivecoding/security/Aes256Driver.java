package edu.cnm.deepdivecoding.security;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;

class Aes256Driver {

	public static void main(String[] main) {
		Character choice = 'X';
		String choiceInput = new String();
		String ciphertext = new String();
		String plaintext = new String();
		String password = new String();
		String salt = new String();

		try {
			BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in));
			System.out.print("Enter password: ");
			password = stdin.readLine();
			do {
				System.out.print("(E)ncrypt, (D)ecrypt, or e(X)it: ");
				choiceInput = stdin.readLine();
				if(choiceInput.length() == 0) {
					throw(new StringIndexOutOfBoundsException("choice cannot be empty"));
				}
				choice = Character.toUpperCase(choiceInput.charAt(0));

				if(choice == 'D') {
					System.out.println("Decrypt mode");
				} else if(choice == 'E') {
					Aes256 aes256 = new Aes256(password);
					salt = aes256.getSalt();
					System.out.println("Salt: " + salt);
					System.out.print("Enter plaintext: ");
					plaintext = stdin.readLine();
					ciphertext = aes256.encrypt(plaintext);
					System.out.println("Ciphertext: " + ciphertext);
				} else if(choice == 'X') {
					// do nothing
				} else {
					System.err.println("Operator error detected. Please enter a valid choice.");
				}
			} while(choice != 'X');
		} catch(Exception exception) {
			System.err.println(exception.getClass().getSimpleName() + ": " + exception.getMessage());
			exception.printStackTrace();
		}
	}
}
