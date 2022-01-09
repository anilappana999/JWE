package com.test.JweImplementation.config;



import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;


public class RSAKeyGenerator {
	public static void keyGenerator() throws InvalidKeySpecException, NoSuchAlgorithmException {
	KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
	//Initialize key size
	keyPairGenerator.initialize(2048);
	// Generate the key pair
	KeyPair keyPair = keyPairGenerator.genKeyPair();

	// Create KeyFactory and RSA Keys Specs
	KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	RSAPublicKeySpec publicKeySpec = keyFactory.getKeySpec(keyPair.getPublic(), RSAPublicKeySpec.class);
	RSAPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(keyPair.getPrivate(), RSAPrivateKeySpec.class);

	// Generate (and retrieve) RSA Keys from the KeyFactory using Keys Specs
	RSAPublicKey publicRsaKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
	

	RSAPrivateKey privateRsaKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
	System.out.println("Generated publicRsaKey"+publicRsaKey);
	System.out.println("Generated privateKeySpec"+privateRsaKey);
	}

}
