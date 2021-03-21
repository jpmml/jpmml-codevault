/*
 * Copyright (c) 2021 Villu Ruusmann
 */
package org.jpmml.codevault;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.GeneralSecurityException;
import java.util.Iterator;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.sun.codemodel.CodeWriter;
import com.sun.codemodel.JCodeModel;
import com.sun.codemodel.JDefinedClass;
import com.sun.codemodel.JPackage;
import com.sun.codemodel.JResourceFile;
import org.jpmml.codemodel.ArchiverUtil;
import org.jpmml.codemodel.CompilerUtil;
import org.jpmml.codemodel.JClassFile;
import org.jpmml.codemodel.JarCodeWriter;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

public class UnlockingURLClassLoaderTest {

	@Test
	public void lockAndUnlock() throws Exception {
		JCodeModel codeModel = new JCodeModel();

		JDefinedClass clazzA = codeModel._package("a")._class("A");
		JDefinedClass clazzB = codeModel._package("b")._class("B")._extends(clazzA);
		JDefinedClass clazzC = codeModel._package("c")._class("C");

		CompilerUtil.compile(codeModel);

		File tmpFile = File.createTempFile("codevault", ".jar");

		URL[] urls = {(tmpFile.toURI()).toURL()};

		try(OutputStream os = new FileOutputStream(tmpFile)){
			Manifest manifest = ArchiverUtil.createManifest();

			CodeWriter codeWriter = new JarCodeWriter(os, manifest);

			codeModel.build(codeWriter);
		}

		try(URLClassLoader classLoader = new PassthroughURLClassLoader(urls)){
			assertNotNull(classLoader.loadClass("a.A"));
			assertNotNull(classLoader.loadClass("b.B"));
			assertNotNull(classLoader.loadClass("c.C"));
		}

		KeyRegistry keyRegistry = new KeyRegistry();

		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");

		SecretKey secretKey = keyGenerator.generateKey();

		lock(keyRegistry, clazzA, secretKey);

		secretKey = keyGenerator.generateKey();

		lock(keyRegistry, clazzC, secretKey);

		try(OutputStream os = new FileOutputStream(tmpFile)){
			Manifest manifest = keyRegistry.toManifest();

			CodeWriter codeWriter = new JarCodeWriter(os, manifest);

			codeModel.build(codeWriter);
		}

		try(URLClassLoader classLoader = new PassthroughURLClassLoader(urls)){

			try {
				assertNotNull(classLoader.loadClass("a.A"));

				fail();
			} catch(ClassFormatError cfe){
				// Ignored
			} // End try

			try {
				assertNotNull(classLoader.loadClass("b.B"));

				fail();
			} catch(ClassFormatError cfe){
				// Ignored
			} // End try

			try {
				assertNotNull(classLoader.loadClass("c.C"));

				fail();
			} catch(ClassFormatError cfe){
				// Ignored
			}
		}

		try(URLClassLoader classLoader = new UnlockingURLClassLoader(urls, keyRegistry)){
			assertNotNull(classLoader.loadClass("a.A"));
			assertNotNull(classLoader.loadClass("b.B"));
			assertNotNull(classLoader.loadClass("c.C"));
		}
	}

	static
	private void lock(KeyRegistry keyRegistry, JDefinedClass clazz, SecretKey secretKey) throws GeneralSecurityException, ReflectiveOperationException {
		JPackage _package = clazz.getPackage();

		for(Iterator<JResourceFile> it = _package.propertyFiles(); it.hasNext(); ){
			JResourceFile resourceFile = it.next();

			if((resourceFile.name()).equals(clazz.name() + ".class")){
				JClassFile classFile = (JClassFile)resourceFile;

				Field bytesField = JClassFile.class.getDeclaredField("bytes");
				if(!bytesField.isAccessible()){
					bytesField.setAccessible(true);
				}

				bytesField.set(classFile, CodeVaultUtil.lock(secretKey, (byte[])bytesField.get(classFile)));
			}
		}

		String secretKeyId = (_package.name()).replace('.', '/') + "/*";

		Attributes attributes = new Attributes();
		attributes.put(AttributeNames.CODEVAULT_ALGORITHM, secretKey.getAlgorithm());
		attributes.put(AttributeNames.CODEVAULT_SECRETKEY_ID, secretKeyId);

		String entryName = (_package.name()).replace('.', '/') + "/" + clazz.name() + ".class";

		keyRegistry.putAttributes(entryName, attributes);
		keyRegistry.putSecretKeyBytes(secretKeyId, secretKey.getEncoded());

	}
}