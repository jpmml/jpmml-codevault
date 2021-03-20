/*
 * Copyright (c) 2021 Villu Ruusmann
 */
package org.jpmml.codevault;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.util.Objects;

import javax.crypto.SecretKey;

public class UnlockingClassLoader extends ClassLoader {

	private KeyRegistry keyRegistry = null;


	public UnlockingClassLoader(ClassLoader parent, KeyRegistry keyRegistry){
		super(parent);

		setKeyRegistry(keyRegistry);
	}

	@Override
	protected Class<?> findClass(String name) throws ClassNotFoundException {
		KeyRegistry keyRegistry = getKeyRegistry();

		String entryName = name.replace('.', '/') + ".class";

		URL url = getResource(entryName);
		if(url == null){
			throw new ClassNotFoundException(name);
		}

		byte[] bytes;

		try(InputStream is = url.openStream()){

			try(ByteArrayOutputStream os = new ByteArrayOutputStream()){
				byte[] buffer = new byte[1024];

				while(true){
					int count = is.read(buffer);
					if(count < 0){
						break;
					}

					os.write(buffer, 0, count);
				}

				bytes = os.toByteArray();
			}
		} catch(IOException ioe){
			throw new RuntimeException(ioe);
		}

		SecretKey secretKey = keyRegistry.getSecretKey(entryName);
		if(secretKey != null){

			try {
				bytes = CodeVaultUtil.unlock(secretKey, bytes);
			} catch(GeneralSecurityException gse){
				throw new RuntimeException(gse);
			}
		}

		return defineClass(name, bytes, 0, bytes.length);
	}

	public KeyRegistry getKeyRegistry(){
		return this.keyRegistry;
	}

	private void setKeyRegistry(KeyRegistry keyRegistry){
		this.keyRegistry = Objects.requireNonNull(keyRegistry);
	}
}