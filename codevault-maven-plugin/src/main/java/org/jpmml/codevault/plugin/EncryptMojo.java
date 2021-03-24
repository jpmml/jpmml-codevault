/*
 * Copyright (c) 2021 Villu Ruusmann
 */
package org.jpmml.codevault.plugin;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.apache.maven.shared.model.fileset.FileSet;
import org.apache.maven.shared.model.fileset.util.FileSetManager;
import org.jpmml.codevault.AttributeNames;
import org.jpmml.codevault.CodeVaultUtil;
import org.jpmml.codevault.KeyRegistry;

@Mojo (
	name = "encrypt",
	defaultPhase = LifecyclePhase.PREPARE_PACKAGE
)
public class EncryptMojo extends AbstractMojo {

	@Parameter (
		defaultValue = "${project}",
		required = true
	)
	private MavenProject project;

	@Parameter (
		defaultValue = "${project.build.directory}/classes"
	)
	private File workDirectory;

	@Parameter
	private String[] includes;

	@Parameter
	private String[] excludes;

	@Parameter (
		defaultValue = "${project.build.directory}/classes/META-INF/CODEVAULT.MF"
	)
	private File manifestFile;

	@Parameter (
		defaultValue = "CLASS"
	)
	private Scope scope;

	@Parameter (
		required = true
	)
	private String algorithm;

	@Parameter (
		defaultValue = "${project.groupId}:${project.artifactId}:${project.version}",
		required = true
	)
	private String secretKeyId;

	@Parameter (
		required = true
	)
	private File secretKeyFile;


	@Override
	public void execute() throws MojoExecutionException {
		File workDirectory = getWorkDirectory();
		String[] includes = getIncludes();
		String[] excludes = getExcludes();
		File manifestFile = getManifestFile();

		FileSetManager fileSetManager = new FileSetManager();

		FileSet fileSet = new FileSet();
		fileSet.setDirectory(workDirectory.getAbsolutePath());

		if(includes != null && includes.length > 0){
			fileSet.setIncludes(Arrays.asList(includes));
		} // End if

		if(excludes != null && excludes.length > 0){
			fileSet.setExcludes(Arrays.asList(excludes));
		}

		Scope scope = getScope();
		String algorithm = getAlgorithm();
		String secretKeyId = getSecretKeyId();
		File secretKeyFile = getSecretKeyFile();

		byte[] secretKeyContent;

		try {
			secretKeyContent = FileUtil.readFile(secretKeyFile);
		} catch(IOException ioe){
			throw new MojoExecutionException("Error reading secret key file", ioe);
		}

		SecretKey secretKey = new SecretKeySpec(secretKeyContent, algorithm);

		KeyRegistry keyRegistry = new KeyRegistry();

		Attributes attributes = new Attributes();
		attributes.put(AttributeNames.CODEVAULT_ALGORITHM, algorithm);
		attributes.put(AttributeNames.CODEVAULT_SECRETKEY_ID, secretKeyId);

		switch(scope){
			case ARCHIVE:
				keyRegistry.addMainAttributes(attributes);
				break;
			case CLASS:
				break;
		}

		String[] includedFiles = fileSetManager.getIncludedFiles(fileSet);
		for(String includedFile : includedFiles){
			File workFile = new File(workDirectory, includedFile);

			byte[] content;

			try {
				content = FileUtil.readFile(workFile);
			} catch(IOException ioe){
				throw new MojoExecutionException("Error reading work file", ioe);
			}

			try {
				content = CodeVaultUtil.encrypt(secretKey, content);
			} catch(GeneralSecurityException gse){
				throw new MojoExecutionException("Error encrypting", gse);
			}

			try {
				FileUtil.writeFile(workFile, content);
			} catch(IOException ioe){
				throw new MojoExecutionException("Error writing work file", ioe);
			}

			switch(scope){
				case ARCHIVE:
					break;
				case CLASS:
					keyRegistry.addAttributes(includedFile, attributes);
					break;
			}
		}

		Manifest manifest = keyRegistry.getManifest();

		FileUtil.ensureParentDirectory(manifestFile);

		try(OutputStream os = new FileOutputStream(manifestFile)){
			Attributes mainAttributes = manifest.getMainAttributes();

			if(!mainAttributes.containsKey(AttributeNames.MANIFEST_VERSION)){
				mainAttributes.put(AttributeNames.MANIFEST_VERSION, "1.0");
			}

			manifest.write(os);
		} catch(IOException ioe){
			throw new MojoExecutionException("Error writing manifest file", ioe);
		}
	}

	public MavenProject getProject(){
		return this.project;
	}

	public void setProject(MavenProject project){
		this.project = project;
	}

	public File getWorkDirectory(){
		return this.workDirectory;
	}

	public void setWorkDirectory(File workDirectory){
		this.workDirectory = workDirectory;
	}

	public String[] getIncludes(){
		return this.includes;
	}

	public void setIncludes(String[] includes){
		this.includes = includes;
	}

	public String[] getExcludes(){
		return this.excludes;
	}

	public void setExcludes(String[] excludes){
		this.excludes = excludes;
	}

	public File getManifestFile(){
		return this.manifestFile;
	}

	public void setManifestFile(File manifestFile){
		this.manifestFile = manifestFile;
	}

	public Scope getScope(){
		return this.scope;
	}

	public void setScope(Scope scope){
		this.scope = scope;
	}

	public String getAlgorithm(){
		return this.algorithm;
	}

	public void setAlgorithm(String algorithm){
		this.algorithm = algorithm;
	}

	public String getSecretKeyId(){
		return this.secretKeyId;
	}

	public void setSecretKeyId(String secretKeyId){
		this.secretKeyId = secretKeyId;
	}

	public File getSecretKeyFile(){
		return this.secretKeyFile;
	}

	public void setSecretKeyFile(File secretKeyFile){
		this.secretKeyFile = secretKeyFile;
	}

	static
	public enum Scope {
		ARCHIVE,
		CLASS,
		;
	}
}