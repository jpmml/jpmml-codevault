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
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class KeyRegistry {

	private Map<String, Attributes> attributes = new LinkedHashMap<>();

	private Map<String, byte[]> encodedKeys = new LinkedHashMap<>();


	public KeyRegistry(){
	}

	public Manifest toManifest(){
		Manifest result = new Manifest();

		Map<String, Attributes> manifestEntries = result.getEntries();

		Collection<Map.Entry<String, Attributes>> entries = this.attributes.entrySet();
		for(Map.Entry<String, Attributes> entry : entries){
			String name = entry.getKey();
			Attributes attributes = entry.getValue();

			manifestEntries.put(name, attributes);
		}

		return result;
	}

	public void load(ClassLoader classLoader) throws IOException {
		Enumeration<URL> urls = classLoader.getResources("META-INF/MANIFEST.MF");

		while(urls.hasMoreElements()){
			URL url = urls.nextElement();

			try(InputStream is = url.openStream()){
				Manifest manifest = new Manifest(is);

				load(manifest);
			}
		}
	}

	public void load(Manifest manifest){
		Map<String, Attributes> manifestEntries = manifest.getEntries();

		Collection<Map.Entry<String, Attributes>> entries = manifestEntries.entrySet();
		for(Map.Entry<String, Attributes> entry : entries){
			String name = entry.getKey();
			Attributes attributes = entry.getValue();

			attributes = extractCodeVaultAttributes(attributes);

			putAttributesInternal(name, attributes);
		}
	}

	public SecretKey getSecretKey(String name){
		Attributes attributes = getAttributes(name);

		if(attributes != null){
			String algorithm = (String)attributes.get(AttributeNames.CODEVAULT_ALGORITHM);
			String secretKeyId = (String)attributes.get(AttributeNames.CODEVAULT_SECRETKEY_ID);

			byte[] encodedKey = getEncodedKey(secretKeyId);
			if(encodedKey == null){
				throw new IllegalArgumentException();
			}

			return new SecretKeySpec(encodedKey, algorithm);
		}

		return null;
	}

	public Attributes getAttributes(String name){
		return this.attributes.get(name);
	}

	public void putAttributes(String name, Attributes attributes){
		attributes = extractCodeVaultAttributes(attributes);

		putAttributesInternal(name, attributes);
	}

	public byte[] getEncodedKey(String id){
		return this.encodedKeys.get(id);
	}

	public void putEncodedKey(String id, byte[] bytes){
		this.encodedKeys.put(id, bytes);
	}

	private void putAttributesInternal(String name, Attributes attributes){

		if(attributes != null && !attributes.isEmpty()){
			this.attributes.put(name, attributes);
		}
	}

	static
	public Attributes extractCodeVaultAttributes(Attributes attributes){
		Attributes result = null;

		Set<? extends Map.Entry<?, ?>> entries = attributes.entrySet();
		for(Map.Entry<?, ?> entry : entries){
			Attributes.Name name = (Attributes.Name)entry.getKey();
			Object value = entry.getValue();

			if(hasCodeVaultPrefix(name)){

				if(result == null){
					result = new Attributes();
				}

				result.put(name, value);
			}
		}

		return result;
	}

	static
	private boolean hasCodeVaultPrefix(Attributes.Name name){
		String stringName = name.toString();

		return (stringName.toUpperCase()).startsWith("X-CODEVAULT-");
	}
}