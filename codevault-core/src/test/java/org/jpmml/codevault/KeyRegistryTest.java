/*
 * Copyright (c) 2021 Villu Ruusmann
 */
package org.jpmml.codevault;

import java.util.jar.Attributes;
import java.util.jar.Manifest;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class KeyRegistryTest {

	@Test
	public void getAttributes(){
		KeyRegistry keyRegistry = new KeyRegistry();

		Manifest manifest = keyRegistry.getManifest();

		Attributes attributes = keyRegistry.getAttributes("a/A.class");

		assertTrue(attributes.isEmpty());

		Attributes mainAttributes = manifest.getMainAttributes();
		mainAttributes.put(AttributeNames.CODEVAULT_ALGORITHM, "AES");
		mainAttributes.put(AttributeNames.CODEVAULT_SECRETKEY_ID, "main-key");

		attributes = keyRegistry.getAttributes("a/A.class");

		assertEquals(2, attributes.size());

		assertEquals("AES", attributes.get(AttributeNames.CODEVAULT_ALGORITHM));
		assertEquals("main-key", attributes.get(AttributeNames.CODEVAULT_SECRETKEY_ID));

		Attributes entryAttributes = new Attributes();
		entryAttributes.put(AttributeNames.CODEVAULT_SECRETKEY_ID, "entry-key");
		entryAttributes.put(new Attributes.Name("X-Flag"), String.valueOf(false));

		keyRegistry.addAttributes("a/A.class", entryAttributes);

		attributes = keyRegistry.getAttributes("a/A.class");

		assertEquals(2, attributes.size());

		assertEquals("AES", attributes.get(AttributeNames.CODEVAULT_ALGORITHM));
		assertEquals("entry-key", attributes.get(AttributeNames.CODEVAULT_SECRETKEY_ID));
	}
}