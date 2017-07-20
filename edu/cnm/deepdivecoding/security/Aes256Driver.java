package edu.cnm.deepdivecoding.security;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;

class Aes256Driver {

	public static void main(String[] main) {
		String password = new String();

			try {
			BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in));
			System.out.print("Enter password: ");
			password = stdin.readLine();
		} catch (IOException ioException) {
			System.err.println("Exception: " + ioException.getMessage());
		}
	}
}
