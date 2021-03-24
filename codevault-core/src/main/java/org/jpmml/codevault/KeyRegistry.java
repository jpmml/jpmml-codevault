/*
 * Copyright (c) 2021 Villu Ruusmann
 */
package org.jpmml.codevault;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Collection;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class KeyRegistry {

	private Manifest manifest = new Manifest();

	private Map<String, byte[]> encodedKeys = new LinkedHashMap<>();


	public KeyRegistry(){
	}

	public void load(ClassLoader classLoader) throws IOException {
		Enumeration<URL> urls = classLoader.getResources("META-INF/MANIFEST.MF");

		while(urls.hasMoreElements()){
			URL url = urls.nextElement();

			try(InputStream is = url.openStream()){
				Manifest manifest = new Manifest(is);

				addMainAttributes(manifest.getMainAttributes());

				Collection<Map.Entry<String, Attributes>> entries = (manifest.getEntries()).entrySet();
				for(Map.Entry<String, Attributes> entry : entries){
					addAttributes(entry.getKey(), entry.getValue());
				}
			}
		}
	}

	public SecretKey getSecretKey(String name){
		Attributes attributes = getAttributes(name);

		return getSecretKey(attributes);
	}

	public SecretKey getSecretKey(Attributes attributes){

		if(attributes != null && !attributes.isEmpty()){
			String algorithm = (String)attributes.get(AttributeNames.CODEVAULT_ALGORITHM);
			String secretKeyId = (String)attributes.get(AttributeNames.CODEVAULT_SECRETKEY_ID);
			if(algorithm == null || secretKeyId == null){
				throw new IllegalArgumentException();
			}

			byte[] encodedKey = getEncodedKey(secretKeyId);
			if(encodedKey == null){
				throw new IllegalArgumentException();
			}

			return new SecretKeySpec(encodedKey, algorithm);
		}

		return null;
	}

	public Attributes getAttributes(String name){
		Manifest manifest = getManifest();

		Attributes result = new Attributes();
		result.putAll(manifest.getMainAttributes());

		Attributes entryAttributes = manifest.getAttributes(name);
		if(entryAttributes != null && !entryAttributes.isEmpty()){
			result.putAll(entryAttributes);
		}

		return result;
	}

	public void addMainAttributes(Attributes attributes){
		Manifest manifest = getManifest();

		Attributes mainAttributes = manifest.getMainAttributes();

		Collection<Map.Entry<Attributes.Name, ?>> entries = (Collection)attributes.entrySet();
		for(Map.Entry<Attributes.Name, ?> entry : entries){

			if(hasCodeVaultPrefix(entry.getKey())){
				mainAttributes.put(entry.getKey(), entry.getValue());
			}
		}
	}

	public void addAttributes(String name, Attributes attributes){
		Manifest manifest = getManifest();

		Attributes entryAttributes = manifest.getAttributes(name);

		Collection<Map.Entry<Attributes.Name, ?>> entries = (Collection)attributes.entrySet();
		for(Map.Entry<Attributes.Name, ?> entry : entries){

			if(hasCodeVaultPrefix(entry.getKey())){

				if(entryAttributes == null){
					entryAttributes = new Attributes();

					(manifest.getEntries()).put(name, entryAttributes);
				}

				entryAttributes.put(entry.getKey(), entry.getValue());
			}
		}
	}

	public Manifest getManifest(){
		return this.manifest;
	}

	public byte[] getEncodedKey(String id){
		return this.encodedKeys.get(id);
	}

	public void putEncodedKey(String id, byte[] bytes){
		this.encodedKeys.put(id, bytes);
	}

	static
	private boolean hasCodeVaultPrefix(Attributes.Name name){
		String stringName = name.toString();

		return (stringName.toUpperCase()).startsWith("X-CODEVAULT-");
	}
}