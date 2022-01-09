package com.test.JweImplementation.config;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.UUID;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;

public class JWEImpl {
	public void JWEEncDec() throws JOSEException, ParseException {
		RSAPrivateKey privateRsaKey = null;
		RSAPublicKey publicRsaKey = null;
		String privateKey = "MIICOAIBADANBgkqhkiG9w0BAQEFAASCAiIwggIeAgEAAoIBAQCw1k3HpBVow3/t7mmHfNBZk7OMEyGKwb0pTU8ljAXJPmv4qb7Xd19lEaWLpnuRv7AXgz18i9KqnGKjoYPplXQcCBB64vFLLKYv90KG4RX3QEqFMwpocqlCL4h2KRjEwdb9B3HF4UyyQwKMCOz2XMKW91Nvsx04Ogcs9MaLELZbG5gUMGbv5XE5G4C5Iz4gcFb+8cSd6UFsQha+ttVubxLZUGI3Y32Ip6Yo0Y2RLflduI8akkJe+EpsCkD3o98+r1wAc/zUitlDRL3YPDb8KD30WqQHtlY6K7e9BD3v8y477zaKOmYumBNgJ+x7jaToXw3V+WKlI3Umq7tYc/z971LFAgEAAoIBABwSqV5cKhnrj0+SXaZophrSW9qM3vJMN19rKnlndTOxeSqMqANErBw7ZPB6iXtl1uqkpwoymEsFcJNRfMOEOl6I2TTo+i1Y9TkAI8uNyBLsXegvZiOWsFAVg7BebdQugZbBq8oiLi7OfIUGlbe2mh2lPdWptaXLcIAui6ZgDNMBlpBFt+TgLa0k/KykKjVoha8vxuNjztMFc4wKq/6p0E8stxgKXpIKWNIHQzX3AVYKyxJUuDpxqD5Y8iLqzK9A4vVl+6CwJyaGVru/HHJMKKbmxWSWKrMhAgEYsfmujTUF3FM815UutWvnuzMOHnAdICPJNxtwI5Oasn7IgUGS8LECAQACAQACAQACAQACAQA=";
		String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsNZNx6QVaMN/7e5ph3zQWZOzjBMhisG9KU1PJYwFyT5r+Km+13dfZRGli6Z7kb+wF4M9fIvSqpxio6GD6ZV0HAgQeuLxSyymL/dChuEV90BKhTMKaHKpQi+IdikYxMHW/QdxxeFMskMCjAjs9lzClvdTb7MdODoHLPTGixC2WxuYFDBm7+VxORuAuSM+IHBW/vHEnelBbEIWvrbVbm8S2VBiN2N9iKemKNGNkS35XbiPGpJCXvhKbApA96PfPq9cAHP81IrZQ0S92Dw2/Cg99FqkB7ZWOiu3vQQ97/MuO+82ijpmLpgTYCfse42k6F8N1flipSN1Jqu7WHP8/e9SxQIDAQAB";
		try {
			publicRsaKey = (RSAPublicKey) KeyEncrypterDecrypter.loadPublicKey(publicKey);
			privateRsaKey = (RSAPrivateKey) KeyEncrypterDecrypter.loadPrivateKey(privateKey);
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		System.out.println("****-----------*****----------");
		JWTClaimsSet.Builder claimsSet = new JWTClaimsSet.Builder();
		claimsSet.issuer("test-user");
		claimsSet.subject("JWE-Authentication-Example");

		// User specified claims
		claimsSet.claim("appId", "230919131512092005");
		claimsSet.claim("userId", "4431d8dc-2f69-4057-9b83-a59385d18c03");
		claimsSet.claim("role", "Admin");
		claimsSet.claim("applicationType", "WEB");
		claimsSet.claim("clientRemoteAddress", "192.168.1.2");

		claimsSet.expirationTime(new Date(new Date().getTime() + 1000 * 60 * 10));
		claimsSet.notBeforeTime(new Date());
		claimsSet.jwtID(UUID.randomUUID().toString());

		System.out.println("Claim Set : \n" + claimsSet.build());

		// Create the JWE header and specify:
		// RSA-OAEP as the encryption algorithm
		// 128-bit AES/GCM as the encryption method
		JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM);

		// Initialized the EncryptedJWT object
		EncryptedJWT jwt = new EncryptedJWT(header, claimsSet.build());
		System.out.println(jwt + "****jwt***");
		// Create an RSA encrypted with the specified public RSA key
		RSAEncrypter encrypter = new RSAEncrypter(publicRsaKey);

		// Doing the actual encryption
		jwt.encrypt(encrypter);

		// Serialize to JWT compact form
		String jwtString = jwt.serialize();
		System.out.println("");
		System.out.println("========================= Encrypted JWE token ==================================");
		System.out.println("");
		System.out.println("\n JWE token : " + jwtString);
		System.out.println("");

		// In order to read back the data from the token using your private RSA key:
		// parse the JWT text string using EncryptedJWT object
		jwt = EncryptedJWT.parse(jwtString);

		// Create a decrypter with the specified private RSA key
		RSADecrypter decrypter = new RSADecrypter(privateRsaKey);

		// Doing the decryption
		jwt.decrypt(decrypter);

		// Print out the claims from decrypted token
		System.out.println("======================== Decrypted payload values ===================================");
		System.out.println("");

		System.out.println("Issuer: [ " + jwt.getJWTClaimsSet().getIssuer() + "]");
		System.out.println("Subject: [" + jwt.getJWTClaimsSet().getSubject() + "]");
		System.out.println("Expiration Time: [" + jwt.getJWTClaimsSet().getExpirationTime() + "]");
		System.out.println("Not Before Time: [" + jwt.getJWTClaimsSet().getNotBeforeTime() + "]");
		System.out.println("JWT ID: [" + jwt.getJWTClaimsSet().getJWTID() + "]");

		System.out.println("Application Id: [" + jwt.getJWTClaimsSet().getClaim("appId") + "]");
		System.out.println("User Id: [" + jwt.getJWTClaimsSet().getClaim("userId") + "]");
		System.out.println("Role type: [" + jwt.getJWTClaimsSet().getClaim("role") + "]");
		System.out.println("Application Type: [" + jwt.getJWTClaimsSet().getClaim("applicationType") + "]");
		System.out.println("Client Remote Address: [" + jwt.getJWTClaimsSet().getClaim("clientRemoteAddress") + "]");

		System.out.println("");
		System.out.println(
				"==========================================================================================================");
	}

}
