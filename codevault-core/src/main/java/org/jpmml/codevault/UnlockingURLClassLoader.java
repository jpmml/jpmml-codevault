/*
 * Copyright (c) 2021 Villu Ruusmann
 */
package org.jpmml.codevault;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.GeneralSecurityException;
import java.util.Objects;
import java.util.jar.Attributes;

import javax.crypto.SecretKey;

public class UnlockingURLClassLoader extends URLClassLoader {

	private KeyRegistry keyRegistry = null;


	public UnlockingURLClassLoader(URL[] urls, KeyRegistry keyRegistry){
		super(urls);

		setKeyRegistry(keyRegistry);
	}

	public UnlockingURLClassLoader(URL[] urls, ClassLoader parent, KeyRegistry keyRegistry){
		super(urls, parent);

		setKeyRegistry(keyRegistry);
	}

	@Override
	protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
		KeyRegistry keyRegistry = getKeyRegistry();

		String entryName = toEntryName(name);

		Attributes attributes = keyRegistry.getAttributes(entryName);
		if(attributes != null){

			synchronized(getClassLoadingLock(name)){
				Class<?> clazz = findLoadedClass(name);

				if(clazz == null){
					clazz = findClass(name);
				} // End if

				if(resolve){
					resolveClass(clazz);
				}

				return clazz;
			}
		}

		return super.loadClass(name, resolve);
	}

	@Override
	protected Class<?> findClass(String name) throws ClassNotFoundException {
		KeyRegistry keyRegistry = getKeyRegistry();

		String entryName = toEntryName(name);

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
			throw new ClassNotFoundException(name, ioe);
		}

		Attributes attributes = keyRegistry.getAttributes(entryName);
		if(attributes != null){
			SecretKey secretKey = keyRegistry.getSecretKey(entryName);
			if(secretKey == null){
				throw new ClassNotFoundException(name);
			}

			try {
				bytes = CodeVaultUtil.unlock(secretKey, bytes);
			} catch(GeneralSecurityException gse){
				throw new ClassNotFoundException(name, gse);
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

	static
	private String toEntryName(String name){
		return name.replace('.', '/') + ".class";
	}

	static {
		ClassLoader.registerAsParallelCapable();
	}
}