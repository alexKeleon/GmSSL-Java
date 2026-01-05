/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package org.gmssl;

import org.junit.Assert;
import org.junit.Test;
import java.io.File;

public class Sm2CertificateRequestTest {

	@Test
	public void testGenerateAndVerifyCsr() {
		// 1. 生成 SM2 密钥对
		Sm2Key key = new Sm2Key();
		key.generateKey();
		System.out.println("Generated SM2 key pair");

		// 2. 创建证书请求
		Sm2CertificateRequest csr = new Sm2CertificateRequest();
		csr.setSubject("CN", "Beijing", "Beijing", "Test Organization", "IT Department", "www.test.com");
		
		// 3. 生成 CSR
		byte[] reqData = csr.generate(key);
		Assert.assertNotNull("CSR data should not be null", reqData);
		Assert.assertTrue("CSR data should have content", reqData.length > 0);
		System.out.println("Generated CSR, length: " + reqData.length + " bytes");

		// 4. 验证 CSR 签名
		boolean verified = csr.verify();
		Assert.assertTrue("CSR signature verification should succeed", verified);
		System.out.println("CSR signature verified: " + verified);

		// 5. 获取并打印主题信息
		String[] subject = csr.getSubject();
		Assert.assertNotNull("Subject should not be null", subject);
		Assert.assertTrue("Subject should have entries", subject.length > 0);
		System.out.println("CSR Subject:");
		for (String s : subject) {
			System.out.println("  " + s);
		}

		// 6. 获取公钥并验证
		Sm2Key pubKey = csr.getSubjectPublicKey();
		Assert.assertNotNull("Public key should not be null", pubKey);
		System.out.println("Extracted public key from CSR");
	}

	@Test
	public void testCsrPemExportImport() {
		// 1. 生成密钥和 CSR
		Sm2Key key = new Sm2Key();
		key.generateKey();

		Sm2CertificateRequest csr = new Sm2CertificateRequest();
		csr.setSubject("CN", "Shanghai", "Shanghai", "Another Org", "Dev", "api.example.com");
		byte[] reqData = csr.generate(key);

		// 2. 导出到 PEM 文件
		String pemFile = "test_request.pem";
		csr.toPem(pemFile);
		System.out.println("Exported CSR to: " + pemFile);

		// 验证文件存在
		File file = new File(pemFile);
		Assert.assertTrue("PEM file should exist", file.exists());

		// 3. 从 PEM 文件导入
		Sm2CertificateRequest csr2 = new Sm2CertificateRequest();
		csr2.fromPem(pemFile);
		System.out.println("Imported CSR from: " + pemFile);

		// 4. 验证导入的 CSR
		boolean verified = csr2.verify();
		Assert.assertTrue("Imported CSR verification should succeed", verified);
		System.out.println("Imported CSR verified: " + verified);

		// 5. 比较主题信息
		String[] subject1 = csr.getSubject();
		String[] subject2 = csr2.getSubject();
		Assert.assertArrayEquals("Subjects should match", subject1, subject2);
		System.out.println("Subject comparison passed");

		// 清理测试文件
		file.delete();
	}

	@Test
	public void testStaticGenerateMethod() {
		// 使用静态方法生成 CSR
		Sm2Key key = new Sm2Key();
		key.generateKey();

		byte[] reqData = Sm2CertificateRequest.generateRequest(
			"CN", "Shenzhen", "Shenzhen", 
			"Static Test Org", "QA", "static.test.com", 
			key);

		Assert.assertNotNull("Static generated CSR should not be null", reqData);
		Assert.assertTrue("Static generated CSR should have content", reqData.length > 0);
		System.out.println("Static method generated CSR, length: " + reqData.length + " bytes");

		// 验证生成的 CSR
		Sm2CertificateRequest csr = new Sm2CertificateRequest();
		// 需要先保存再读取来验证
		String pemFile = "test_static_request.pem";
		GmSSLJNI.x509_req_to_pem(reqData, pemFile);
		csr.fromPem(pemFile);
		
		boolean verified = csr.verify();
		Assert.assertTrue("Static generated CSR verification should succeed", verified);
		System.out.println("Static generated CSR verified: " + verified);

		// 清理
		new File(pemFile).delete();
	}

	@Test
	public void testMinimalCsr() {
		// 测试只设置 CommonName 的最小 CSR
		Sm2Key key = new Sm2Key();
		key.generateKey();

		Sm2CertificateRequest csr = new Sm2CertificateRequest();
		csr.setCommonName("minimal.test.com");
		byte[] reqData = csr.generate(key);

		Assert.assertNotNull("Minimal CSR should not be null", reqData);
		boolean verified = csr.verify();
		Assert.assertTrue("Minimal CSR verification should succeed", verified);
		System.out.println("Minimal CSR (CN only) generated and verified");
	}

	@Test
	public void testCustomSignerId() {
		// 测试自定义 signer ID
		Sm2Key key = new Sm2Key();
		key.generateKey();

		String customSignerId = "custom@signer.id";

		Sm2CertificateRequest csr = new Sm2CertificateRequest();
		csr.setSubject("CN", "Hangzhou", "Hangzhou", "Custom ID Org", "Security", "custom.id.test.com");
		byte[] reqData = csr.generate(key, customSignerId);

		Assert.assertNotNull("CSR with custom signer ID should not be null", reqData);

		// 使用相同的 signer ID 验证
		boolean verified = csr.verify(customSignerId);
		Assert.assertTrue("CSR with custom signer ID verification should succeed", verified);
		System.out.println("CSR with custom signer ID generated and verified");

		// 使用默认 signer ID 验证应该失败
		boolean verifiedWithDefault = csr.verify();
		Assert.assertFalse("CSR verification with wrong signer ID should fail", verifiedWithDefault);
		System.out.println("CSR verification with wrong signer ID correctly failed");
	}
}
