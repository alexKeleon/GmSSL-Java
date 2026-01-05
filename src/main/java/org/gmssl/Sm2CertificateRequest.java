/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package org.gmssl;

/**
 * SM2 Certificate Request (CSR) class.
 * 
 * This class provides functionality to generate and manage X.509 Certificate
 * Signing Requests (CSR) using SM2 algorithm, equivalent to the `gmssl reqgen` command.
 * 
 * Example usage:
 * <pre>
 * // Generate a new key pair
 * Sm2Key key = new Sm2Key();
 * key.generateKey();
 * 
 * // Create a certificate request
 * Sm2CertificateRequest csr = new Sm2CertificateRequest();
 * csr.setSubject("CN", "Beijing", "Beijing", "MyOrg", "MyUnit", "www.example.com");
 * byte[] reqData = csr.generate(key);
 * 
 * // Export to PEM file
 * csr.toPem("request.pem");
 * </pre>
 */
public class Sm2CertificateRequest {

	public static final String DEFAULT_ID = GmSSLJNI.SM2_DEFAULT_ID;

	private byte[] req = null;

	// Subject fields
	private String country = null;
	private String state = null;
	private String locality = null;
	private String organization = null;
	private String organizationalUnit = null;
	private String commonName = null;

	public Sm2CertificateRequest() {
	}

	/**
	 * Set the subject distinguished name fields.
	 * 
	 * @param country Country code (C), e.g., "CN"
	 * @param state State or province name (ST), e.g., "Beijing"
	 * @param locality Locality name (L), e.g., "Beijing"
	 * @param organization Organization name (O), e.g., "MyCompany"
	 * @param organizationalUnit Organizational unit name (OU), e.g., "IT Department"
	 * @param commonName Common name (CN), e.g., "www.example.com" - REQUIRED
	 */
	public void setSubject(String country, String state, String locality,
			String organization, String organizationalUnit, String commonName) {
		if (commonName == null || commonName.isEmpty()) {
			throw new GmSSLException("Common name (CN) is required");
		}
		this.country = country;
		this.state = state;
		this.locality = locality;
		this.organization = organization;
		this.organizationalUnit = organizationalUnit;
		this.commonName = commonName;
	}

	/**
	 * Set only the common name (CN) for simple use cases.
	 * 
	 * @param commonName Common name (CN), e.g., "www.example.com"
	 */
	public void setCommonName(String commonName) {
		if (commonName == null || commonName.isEmpty()) {
			throw new GmSSLException("Common name (CN) is required");
		}
		this.commonName = commonName;
	}

	/**
	 * Generate a certificate request using the provided SM2 key pair.
	 * Uses the default SM2 signer ID.
	 * 
	 * @param key SM2 key pair (must contain private key)
	 * @return The DER-encoded certificate request
	 */
	public byte[] generate(Sm2Key key) {
		return generate(key, DEFAULT_ID);
	}

	/**
	 * Generate a certificate request using the provided SM2 key pair and signer ID.
	 * 
	 * @param key SM2 key pair (must contain private key)
	 * @param signerId SM2 signer ID for signature
	 * @return The DER-encoded certificate request
	 */
	public byte[] generate(Sm2Key key, String signerId) {
		if (this.commonName == null) {
			throw new GmSSLException("Common name (CN) must be set before generating CSR");
		}
		if (key == null) {
			throw new GmSSLException("SM2 key is required");
		}

		long sm2Key = key.getPrivateKey();
		this.req = GmSSLJNI.x509_req_new(
			this.country, this.state, this.locality,
			this.organization, this.organizationalUnit, this.commonName,
			sm2Key, signerId);

		if (this.req == null) {
			throw new GmSSLException("Failed to generate certificate request");
		}
		return this.req;
	}

	/**
	 * Get the DER-encoded certificate request data.
	 * 
	 * @return The DER-encoded certificate request, or null if not generated
	 */
	public byte[] getRequest() {
		return this.req;
	}

	/**
	 * Export the certificate request to a PEM file.
	 * 
	 * @param file Path to the output PEM file
	 */
	public void toPem(String file) {
		if (this.req == null) {
			throw new GmSSLException("No certificate request to export");
		}
		if (file == null || file.isEmpty()) {
			throw new GmSSLException("File path is required");
		}
		if (GmSSLJNI.x509_req_to_pem(this.req, file) != 1) {
			throw new GmSSLException("Failed to export certificate request to PEM");
		}
	}

	/**
	 * Import a certificate request from a PEM file.
	 * 
	 * @param file Path to the PEM file
	 */
	public void fromPem(String file) {
		if (file == null || file.isEmpty()) {
			throw new GmSSLException("File path is required");
		}
		this.req = GmSSLJNI.x509_req_from_pem(file);
		if (this.req == null) {
			throw new GmSSLException("Failed to import certificate request from PEM");
		}
	}

	/**
	 * Get the subject distinguished name from the certificate request.
	 * 
	 * @return Array of subject name components (e.g., ["C:CN", "ST:Beijing", "CN:www.example.com"])
	 */
	public String[] getSubject() {
		if (this.req == null) {
			throw new GmSSLException("No certificate request loaded");
		}
		String[] subject = GmSSLJNI.x509_req_get_subject(this.req);
		if (subject == null) {
			throw new GmSSLException("Failed to get subject from certificate request");
		}
		return subject;
	}

	/**
	 * Get the subject public key from the certificate request.
	 * 
	 * @return SM2 public key
	 */
	public Sm2Key getSubjectPublicKey() {
		if (this.req == null) {
			throw new GmSSLException("No certificate request loaded");
		}
		long sm2Pub = GmSSLJNI.x509_req_get_subject_public_key(this.req);
		if (sm2Pub == 0) {
			throw new GmSSLException("Failed to get subject public key from certificate request");
		}
		return new Sm2Key(sm2Pub, false);
	}

	/**
	 * Verify the signature of the certificate request.
	 * Uses the default SM2 signer ID.
	 * 
	 * @return true if verification succeeds, false otherwise
	 */
	public boolean verify() {
		return verify(DEFAULT_ID);
	}

	/**
	 * Verify the signature of the certificate request with specified signer ID.
	 * 
	 * @param signerId SM2 signer ID used for verification
	 * @return true if verification succeeds, false otherwise
	 */
	public boolean verify(String signerId) {
		if (this.req == null) {
			throw new GmSSLException("No certificate request loaded");
		}
		int ret = GmSSLJNI.x509_req_verify(this.req, signerId);
		if (ret < 0) {
			throw new GmSSLException("Failed to verify certificate request");
		}
		return ret == 1;
	}

	/**
	 * Static method to generate a certificate request directly.
	 * 
	 * @param country Country code (C)
	 * @param state State or province name (ST)
	 * @param locality Locality name (L)
	 * @param organization Organization name (O)
	 * @param organizationalUnit Organizational unit name (OU)
	 * @param commonName Common name (CN) - REQUIRED
	 * @param key SM2 key pair
	 * @param signerId SM2 signer ID
	 * @return The DER-encoded certificate request
	 */
	public static byte[] generateRequest(
			String country, String state, String locality,
			String organization, String organizationalUnit, String commonName,
			Sm2Key key, String signerId) {
		Sm2CertificateRequest csr = new Sm2CertificateRequest();
		csr.setSubject(country, state, locality, organization, organizationalUnit, commonName);
		return csr.generate(key, signerId);
	}

	/**
	 * Static method to generate a certificate request with default signer ID.
	 * 
	 * @param country Country code (C)
	 * @param state State or province name (ST)
	 * @param locality Locality name (L)
	 * @param organization Organization name (O)
	 * @param organizationalUnit Organizational unit name (OU)
	 * @param commonName Common name (CN) - REQUIRED
	 * @param key SM2 key pair
	 * @return The DER-encoded certificate request
	 */
	public static byte[] generateRequest(
			String country, String state, String locality,
			String organization, String organizationalUnit, String commonName,
			Sm2Key key) {
		return generateRequest(country, state, locality, organization, organizationalUnit,
			commonName, key, DEFAULT_ID);
	}
}
