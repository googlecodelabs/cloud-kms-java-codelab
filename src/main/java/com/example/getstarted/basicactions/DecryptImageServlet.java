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

package com.example.getstarted.basicactions;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.example.getstarted.util.CloudKeyManagementServiceHelper;
import com.google.cloud.storage.Storage.BlobSourceOption;
import com.google.cloud.storage.BlobId;
import com.google.cloud.storage.BlobInfo;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;
import com.google.firebase.internal.Log;

//[START example]
@SuppressWarnings("serial")
// [START annotations]
@MultipartConfig
@WebServlet(name = "image", urlPatterns = { "/image" })
// [END annotations]
public class DecryptImageServlet extends HttpServlet {

	@Override
	// [START doGet]
	public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
		// Initialize credential.
		try {
			// ensure request parameter include gcsurl
			if (req.getParameter("imgurl") != null && req.getParameter("imgurl").length() > 0) {
				// retrieve the gcs url and decode it
				URI gcsImageUri = URI.create(java.net.URLDecoder.decode(req.getParameter("imgurl"), "UTF-8"));

				// parse gcs-stored file name
				File fileMediaFile = new File(gcsImageUri.toURL().getFile());
				String fileMediaFileName = fileMediaFile.getName();

				// Initialize a Google Cloud Storage client
				// to retrieve the encrypted/decrypted image
				Storage storage = StorageOptions.getDefaultInstance().getService();

				// Download the wrapped-Data Encryption Key (DEK)
				// from Google Cloud Storage (GCS)
				byte[] wDEKbytes = storage.readAllBytes(getServletContext().getInitParameter("bookshelf.bucket"),
						(fileMediaFileName + "-wDEK.key"));

				// Ask Google Key Management Service (KMS) to unwrap the wDEK
				// Using the default Google App Engine (GAE) credential
				CloudKeyManagementServiceHelper kmsHelper = new CloudKeyManagementServiceHelper(
						getServletContext().getInitParameter("projectID"),
						getServletContext().getInitParameter("bookshelf.keyRingName"),
						getServletContext().getInitParameter("bookshelf.keyRingLocation"),
						getServletContext().getInitParameter("bookshelf.keyName"));
				SecretKey DEK = kmsHelper.unwrapDataEncryptionKey(wDEKbytes);

				// Download the image file from Google Cloud Storage (GCS)
				// Ask GCS to decrypt the file using the DEK
				BlobId blobId = BlobId.of(getServletContext().getInitParameter("bookshelf.bucket"), fileMediaFileName);
				BlobInfo storageBlob = storage.get(blobId);
				// TODO: download wDEK from metadata instead of seperate file
				// Map<String, String> metadata = storageBlob.getMetadata();
				byte[] content = storage.readAllBytes(blobId, BlobSourceOption.decryptionKey(DEK));

				// Set the response type as the image file content type
				resp.setContentType(storageBlob.getContentType());

				// Write the contents of the decrypted file
				resp.getOutputStream().write(content);
			} else {
				// TODO: write a default image
			}
		} catch (IOException e) {
			// TODO
			e.printStackTrace();
		}
	}
	// [START doGet]
}
// [END example]