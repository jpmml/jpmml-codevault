/*
 * Copyright (c) 2021 Villu Ruusmann
 */
package org.jpmml.codevault.plugin;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public class FileUtil {

	private FileUtil(){
	}

	static
	public byte[] readFile(File file) throws IOException {
		return Files.readAllBytes(file.toPath());
	}

	static
	public void writeFile(File file, byte[] bytes) throws IOException {
		ensureParentDirectory(file);

		Files.write(file.toPath(), bytes);
	}

	static
	public File ensureParentDirectory(File file){
		File parent = file.getParentFile();
		if(!parent.exists()){
			parent.mkdirs();
		}

		return parent;
	}
}