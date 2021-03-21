/*
 * Copyright (c) 2021 Villu Ruusmann
 */
package org.jpmml.codevault;

import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.Cipher;

public class CodeVaultUtil {

	private CodeVaultUtil(){
	}

	static
	public byte[] lock(Key key, byte[] content) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance(key.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, key);

		return cipher.doFinal(content);
	}

	static
	public byte[] unlock(Key key, byte[] content) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance(key.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, key);

		return cipher.doFinal(content);
	}
}