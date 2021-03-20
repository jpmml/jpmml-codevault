/*
 * Copyright (c) 2021 Villu Ruusmann
 */
package org.jpmml.codevault;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class CodeVaultUtil {

	private CodeVaultUtil(){
	}

	static
	public byte[] lock(SecretKey secretKey, byte[] content) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);

		return cipher.doFinal(content);
	}

	static
	public byte[] unlock(SecretKey secretKey, byte[] content) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, secretKey);

		return cipher.doFinal(content);
	}
}