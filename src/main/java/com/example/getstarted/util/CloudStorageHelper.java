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

import com.google.cloud.storage.Blob;
import com.google.cloud.storage.BlobId;
import com.google.cloud.storage.BlobInfo;
import com.google.cloud.storage.Storage.BlobWriteOption;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;

// [START example]
public class CloudStorageHelper {

	private static Storage storage = null;

	// [START init]
	static {
		storage = StorageOptions.getDefaultInstance().getService();
	}
	// [END init]

	// [START uploadFile]
	/**
	 * Uploads a file to Google Cloud Storage to the bucket specified in the
	 * BUCKET_NAME environment variable, appending a timestamp to end of the
	 * uploaded filename.
	 */
	public String uploadFile(Part filePart, final String bucketName, CloudKeyManagementServiceHelper kmsHelper,
			SecretKey DEK, SecretKey wDEK) throws IOException {
		DateTimeFormatter dtf = DateTimeFormat.forPattern("-YYYY-MM-dd-HHmmssSSS");
		DateTime dt = DateTime.now(DateTimeZone.UTC);
		String dtString = dt.toString(dtf);
		final String fileName = filePart.getSubmittedFileName() + dtString;

		try {

			Map<String, String> metadataMap = new HashMap<String, String>();
			metadataMap.put("wDEK", new String(kmsHelper.encodeSecretKey(wDEK), "utf-8"));

			BlobId blobId = BlobId.of(bucketName, fileName);
			BlobInfo blobInfo = BlobInfo.newBuilder(blobId).setContentType(filePart.getContentType())
					.setMetadata(metadataMap).build();
			BlobWriteOption blobWriteOpts = BlobWriteOption.encryptionKey(DEK);
			Blob blob = storage.create(blobInfo, filePart.getInputStream(), blobWriteOpts);

			return blob.getMediaLink();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
	}

	public String uploadSecurityKey(SecretKey key, CloudKeyManagementServiceHelper kmsHelper, String keyName,
			final String bucketName) throws IOException {
		final String fileName = keyName;

		// the inputstream is closed by default, so we don't need to close it
		// here
		BlobInfo blobInfo = storage.create(
				BlobInfo.newBuilder(bucketName, fileName).setContentType("text/plain").build(),
				kmsHelper.encodeSecretKey(key));
		// return the public download link
		return blobInfo.getMediaLink();
	}
	// [END uploadFile]

	// [START getImageUrl]
	/**
	 * Extracts the file payload from an HttpServletRequest, checks that the
	 * file extension is supported and uploads the file to Google Cloud Storage.
	 * 
	 */
	public String getImageUrl(HttpServletRequest req, HttpServletResponse resp, final String bucket,
			final String projectId, final String keyRingName, final String keyRingLocation, final String keyName)
			throws IOException, ServletException {
		try {
			// Init a Cloud KMS helper
			CloudKeyManagementServiceHelper kmsHelper = new CloudKeyManagementServiceHelper(projectId, keyRingName,
					keyRingLocation, keyName);

			// Generate a new Data Encryption Key (DEK)
			SecretKey DEK = kmsHelper.generateDataEncryptionKey();

			// Ask Google Cloud Key Management Service (KMS)
			// to wrap (encrypt) the Data Encryption Key
			// returning a wrapped-DEK (wDEK)
			SecretKey wDEK = kmsHelper.wrapDataEncryptionKey(DEK);

			Part filePart = req.getPart("file");
			final String fileName = filePart.getSubmittedFileName();

			String imageUrl = req.getParameter("imageUrl");
			// Check extension of file
			if (fileName != null && !fileName.isEmpty() && fileName.contains(".")) {
				final String extension = fileName.substring(fileName.lastIndexOf('.') + 1);
				String[] allowedExt = { "jpg", "jpeg", "png", "gif" };
				for (String s : allowedExt) {
					if (extension.equals(s)) {
						// retrieve the key
						String fileMediaLink = this.uploadFile(filePart, bucket, kmsHelper, DEK, wDEK);

						// remove query parameters
						String fileMediaLinkClean = fileMediaLink.substring(0, fileMediaLink.lastIndexOf("?"));

						// parse gcs-stored file name
						File fileMediaFile = new File(URI.create(fileMediaLinkClean).toURL().getFile());
						String fileMediaFileName = fileMediaFile.getName();

						// Upload the KMS wrapped Data Encryption Key (DEK)
						// to Google Cloud Storage (GCS) for long-term storage
						// name the file {imagename} + -wDEK.key
						String wDEKUrl = uploadSecurityKey(wDEK, kmsHelper, (fileMediaFileName + "-wDEK.key"), bucket);

						return fileMediaLinkClean;
					}
				}
				throw new ServletException("file must be an image");
			}
			return imageUrl;
		} catch (NoSuchAlgorithmException e1) {
			// TODO
			return null;
		}
	}
	// [END getImageUrl]
}
// [END example]
