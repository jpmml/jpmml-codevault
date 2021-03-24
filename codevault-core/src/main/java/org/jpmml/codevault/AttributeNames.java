/*
 * Copyright (c) 2021 Villu Ruusmann
 */
package org.jpmml.codevault;

import java.util.jar.Attributes;

public interface AttributeNames {

	Attributes.Name MANIFEST_VERSION = Attributes.Name.MANIFEST_VERSION;

	Attributes.Name CODEVAULT_ALGORITHM = new Attributes.Name("X-CodeVault-Algorithm");
	Attributes.Name CODEVAULT_SECRETKEY_ID = new Attributes.Name("X-CodeVault-SecretKey-Id");
}