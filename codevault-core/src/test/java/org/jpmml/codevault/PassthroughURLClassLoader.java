/*
 * Copyright (c) 2021 Villu Ruusmann
 */
package org.jpmml.codevault;

import java.net.URL;
import java.net.URLClassLoader;

class PassthroughURLClassLoader extends URLClassLoader {

	PassthroughURLClassLoader(URL[] urls){
		super(urls);
	}

	static {
		ClassLoader.registerAsParallelCapable();
	}
}