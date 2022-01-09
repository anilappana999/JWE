package com.test.JweImplementation.config;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class KeyEncrypterDecrypter {
	public static Key loadPrivateKey(String key64) throws GeneralSecurityException, IOException {
		byte[] clear = Base64.getDecoder().decode(key64.getBytes());
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(clear);
		KeyFactory fact = KeyFactory.getInstance("RSA");
		PrivateKey priv = fact.generatePrivate(keySpec);
		Arrays.fill(clear, (byte) 0);
		return priv;

	}

	public static Key loadPublicKey(String stored) throws GeneralSecurityException, IOException {
		byte[] data = Base64.getDecoder().decode((stored.getBytes()));
		X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
		KeyFactory fact = KeyFactory.getInstance("RSA");
		return fact.generatePublic(spec);

	}
}
