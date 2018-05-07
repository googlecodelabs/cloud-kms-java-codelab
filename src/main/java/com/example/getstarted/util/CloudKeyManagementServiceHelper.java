/*
 * Copyright 2016 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.example.getstarted.util;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Collections;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.cloudkms.v1.CloudKMS;
import com.google.api.services.cloudkms.v1.model.DecryptRequest;
import com.google.api.services.cloudkms.v1.model.DecryptResponse;
import com.google.api.services.cloudkms.v1.model.EncryptRequest;
import com.google.api.services.cloudkms.v1.model.EncryptResponse;

//[START example]
public class CloudKeyManagementServiceHelper {
	protected String project_name;
	protected String location;
	protected String keyRingId;
	protected String cryptoKeyId;

	public static GoogleCredential credential = null;
	public static CloudKMS kmsClient = null;

	// [START init]
	public CloudKeyManagementServiceHelper(final String projectId, final String keyRingName,
			final String keyRingLocation, final String keyName) throws IOException {
		// ensure the required parameters are provided
		if (projectId != null && keyRingName != null && keyRingLocation != null && keyName != null
				&& projectId.length() > 0 && keyRingName.length() > 0 && keyRingLocation.length() > 0
				&& keyName.length() > 0) {
			// set the global variables
			project_name = projectId;
			keyRingId = keyRingName;
			location = keyRingLocation;
			cryptoKeyId = keyName;

			// Request the default Google App Engine (GAE) credentials
			// Used to communicate with the Google Cloud KMS
			// GAE Service Account can be managed in Cloud IAM
			try {
				credential = GoogleCredential.getApplicationDefault()
						.createScoped(Collections.singleton("https://www.googleapis.com/auth/cloud-platform"));

				// Build a Cloud Key Management Service (KMS) client
				// To execute encrypt/decrypt key requests
				kmsClient = new CloudKMS.Builder(new NetHttpTransport(), JacksonFactory.getDefaultInstance(),
						credential).setApplicationName("Crypter").build();
			} catch (IOException e) {
				e.printStackTrace();
				throw e;
			}
		} else {
			throw new IOException(
					"Required input to Cloud KMS Helper missing: " + "projectId: " + project_name + ", " + "keyRingId: "
							+ keyRingId + ", " + "location: " + location + ", " + "cryptoKeyId: " + cryptoKeyId);
		}
	}
	// [END init]

	// [START generateDataEncryptionKey]
	public SecretKey generateDataEncryptionKey() throws NoSuchAlgorithmException {
		// Get the KeyGenerator
		KeyGenerator kgen;
		SecretKey DEK;
		try {
			// Get an instance of the key generator
			// with Advanced Encryption Standard (AES)
			// Set to 256 bit encryption
			kgen = KeyGenerator.getInstance("AES");
			kgen.init(256); // 256 bit encryption

			// generate a Data Encryption Key (DEK
			DEK = kgen.generateKey();
		} catch (NoSuchAlgorithmException e1) {
			throw e1;
		}

		// return the key
		return DEK;
	}
	// [END generateDataEncryptionKey]

	// [START encodeSecretKey]
	public byte[] encodeSecretKey(SecretKey key) {
		return Base64.getEncoder().encode(key.getEncoded());
	}
	// [END encodeSecretKey]

	// [START decodeSecretKey]
	public byte[] decodeSecretKey(SecretKey key) {
		return Base64.getDecoder().decode(key.getEncoded());
	}
	// [END decodeSecretKey]

	// [START wrapDataEncryptionKey]
	public SecretKey wrapDataEncryptionKey(SecretKey DEK) throws IOException {
		// Define the cryptographic key resource path
		String cryptoKeyName = "projects/" + project_name + "/locations/" + location + "/keyRings/" + keyRingId
				+ "/cryptoKeys/" + cryptoKeyId;

		// Define a request to Google Cloud KMS to encode a Key
		EncryptRequest request = new EncryptRequest().encodePlaintext(DEK.getEncoded());

		// Execute the encrypt request to Google Cloud KMS
		EncryptResponse response = kmsClient.projects().locations().keyRings().cryptoKeys()
				.encrypt(cryptoKeyName, request).execute();

		// Parse the response as a wrapped Data Encryption Key (wDEK)
		SecretKey wDEK = new SecretKeySpec(response.decodeCiphertext(), 0, response.decodeCiphertext().length, "AES");

		// Return the key
		return wDEK;
	}
	// [END wrapDataEncryptionKey]

	// [END unwrapDataEncryptionKey]
	public SecretKey unwrapDataEncryptionKey(byte[] wDEK) throws IOException {
		// Define the cryptographic key resource path
		String cryptoKeyName = "projects/" + project_name + "/locations/" + location + "/keyRings/" + keyRingId
				+ "/cryptoKeys/" + cryptoKeyId;

		// Define a request to Google Cloud KMS to encode a Key
		DecryptRequest decryptRequest = new DecryptRequest().encodeCiphertext(Base64.getDecoder().decode(wDEK));

		// Execute the decrypt request to Google Cloud KMS
		DecryptResponse decryptResponse = kmsClient.projects().locations().keyRings().cryptoKeys()
				.decrypt(cryptoKeyName, decryptRequest).execute();

		// Parse the response as a unwrapped Data Encryption Key (DEK)
		SecretKey DEK = new SecretKeySpec(decryptResponse.decodePlaintext(), 0,
				decryptResponse.decodePlaintext().length, "AES");

		// return the key
		return DEK;
	}
	// [END unwrapDataEncryptionKey]

}
// [END example]
