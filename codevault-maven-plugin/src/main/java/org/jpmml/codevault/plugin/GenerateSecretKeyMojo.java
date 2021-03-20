/*
 * Copyright (c) 2021 Villu Ruusmann
 */
package org.jpmml.codevault.plugin;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;

@Mojo (
	name = "generate-secretkey"
)
public class GenerateSecretKeyMojo extends AbstractMojo {

	@Parameter (
		defaultValue = "${project}",
		required = true
	)
	private MavenProject project;

	@Parameter (
		required = true
	)
	private String algorithm;

	@Parameter (
		required = true
	)
	private File secretKeyFile;


	@Override
	public void execute() throws MojoExecutionException {
		String algorithm = getAlgorithm();
		File secretKeyFile = getSecretKeyFile();

		KeyGenerator keyGenerator;

		try {
			keyGenerator = KeyGenerator.getInstance(algorithm);
		} catch(GeneralSecurityException gse){
			throw new MojoExecutionException("Error obtaining secret key generator", gse);
		}

		SecretKey secretKey = keyGenerator.generateKey();

		byte[] secretKeyBytes = secretKey.getEncoded();
		if(secretKeyBytes == null){
			throw new MojoExecutionException("Error obtaining the primary encoded format of the secret key");
		}

		try {
			FileUtil.writeFile(secretKeyFile, secretKeyBytes);
		} catch(IOException ioe){
			throw new MojoExecutionException("Error writing secret key file", ioe);
		}
	}

	public MavenProject getProject(){
		return this.project;
	}

	public void setProject(MavenProject project){
		this.project = project;
	}

	public String getAlgorithm(){
		return this.algorithm;
	}

	public void setAlgorithm(String algorithm){
		this.algorithm = algorithm;
	}

	public File getSecretKeyFile(){
		return this.secretKeyFile;
	}

	public void setSecretKeyFile(File secretKeyFile){
		this.secretKeyFile = secretKeyFile;
	}
}