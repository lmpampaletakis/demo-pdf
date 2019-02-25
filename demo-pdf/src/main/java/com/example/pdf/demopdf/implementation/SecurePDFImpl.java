package com.example.pdf.demopdf.implementation;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.Enumeration;

import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.example.pdf.demopdf.custom.CustomTSAClient;
import com.example.pdf.demopdf.intraface.SecurePDFIntf;
import com.itextpdf.kernel.pdf.EncryptionConstants;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfStream;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.ReaderProperties;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.kernel.pdf.WriterProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.CrlClientOnline;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.LtvVerification;
import com.itextpdf.signatures.OCSPVerifier;
import com.itextpdf.signatures.OcspClientBouncyCastle;
import com.itextpdf.signatures.PdfSignatureAppearance;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PrivateKeySignature;
import com.itextpdf.signatures.TSAClientBouncyCastle;

@Service
public class SecurePDFImpl implements SecurePDFIntf {

	private static final Logger LOG = LoggerFactory.getLogger(SecurePDFImpl.class);

	@Value("${keystore}")
	private String keystore;

	@Value("${keystore.password}")
	private String keystorePassword;

	@Value("${tsa.client}")
	private String tsaClient;

	@Value("${tsa.ca}")
	private String tsaca;

	@Value("${pk.alias}")
	private String keyAlias;
	
	@Value("${num.certificates}")
	private int numOfCertificates;

	private final static String PDF_PASS_OWNER = "password";
	private final static String SIGNATURE_FIELD = "Signature";

	@Override
	public void signPDF(InputStream is, HttpServletResponse response) throws IOException, KeyStoreException,
			CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
		LOG.debug("Inside signPDF...");
		Security.addProvider(new BouncyCastleProvider());
		// Signs pdf
		try (OutputStream signedResult = response.getOutputStream()) {
			sign(is, signedResult, SIGNATURE_FIELD, PdfSigner.CryptoStandard.CADES, 0, true, PDF_PASS_OWNER.getBytes());
		}

	}
/**
 * 
 * @param original The original stream of PDF
 * @param os The outputstream that the ltv enabled PDF will be written
 * @param name The name of the signature
 * @param subfilter The cryptographic standard
 * @param certificationLevel
 * @param isAppendMode
 * @param password
 */
	void sign(InputStream original, OutputStream os, String name, PdfSigner.CryptoStandard subfilter,
			int certificationLevel, boolean isAppendMode, byte[] password) {

		byte[] encrypted = null;
		OutputStream encryptedResult = new ByteArrayOutputStream();
		try {
			encrypt(original, encryptedResult, PDF_PASS_OWNER.getBytes());
		} catch (IOException e1) {
			LOG.error("Error while encrypting...", e1);
		}
		encrypted = ((ByteArrayOutputStream) encryptedResult).toByteArray();

		try (InputStream encryptedSource = new ByteArrayInputStream(encrypted);
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				PdfReader reader = new PdfReader(encryptedSource, new ReaderProperties().setPassword(password))) {

			PdfSigner signer = new PdfSigner(reader, baos,
					new StampingProperties().preserveEncryption().useAppendMode());
			CustomTSAClient tsc = new CustomTSAClient(new TSAClientBouncyCastle(tsaClient, "", ""), 4);
			// getting keystore
			KeyStore ks = getKeyStore();
			Certificate[] chain = getCertificateChain(ks);
			setPdfSignatureAppearance(signer);
			setSignProps(signer, certificationLevel, name);
			String digestAlgorithm = DigestAlgorithms.SHA256;
			PrivateKey pk = (PrivateKey) ks.getKey(keyAlias, keystorePassword.toCharArray());
			IExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
			OCSPVerifier ocspVerifier = new OCSPVerifier(null, null);
			OcspClientBouncyCastle ocspClient = new OcspClientBouncyCastle(ocspVerifier);
			CrlClientOnline crlClient = new CrlClientOnline();
			signer.signDetached(new BouncyCastleDigest(), pks, chain, Collections.singleton(crlClient), ocspClient, tsc,
					0, subfilter);
			ltvEnable(signer, baos, os, name, ocspClient, crlClient, tsc);

		} catch (IOException | GeneralSecurityException e) {
			LOG.error("Error reading stream", e);
		}

	}

	/**
	 * 
	 * @param signer The PDF signer
	 * @param signedPdfStream The ByteArrayOutputStream to read the PDF
	 * @param os The OutputStream to write the PDF
	 * @param name The name of the signature
	 * @param ocspClient
	 * @param crlClient
	 * @param tsc The TSA 
	 */
	private void ltvEnable(PdfSigner signer, ByteArrayOutputStream baos, OutputStream os, String name,
			OcspClientBouncyCastle ocspClient, CrlClientOnline crlClient, CustomTSAClient tsc) {
		ByteArrayInputStream signedPdfInput = new ByteArrayInputStream(baos.toByteArray());
		try {
			PdfReader pdfReader = new PdfReader(signedPdfInput);
			PdfDocument document = new PdfDocument(pdfReader.setUnethicalReading(true), new PdfWriter(os),
					new StampingProperties().useAppendMode());
			LtvVerification ltvVerification = new LtvVerification(document);
			ltvVerification.addVerification(name, ocspClient, crlClient, LtvVerification.CertificateOption.WHOLE_CHAIN,
					LtvVerification.Level.OCSP_CRL, LtvVerification.CertificateInclusion.YES);
			ltvVerification.merge();
			document.getCatalog().getPdfObject().getAsDictionary(PdfName.DSS).getAsArray(PdfName.Certs)
					.add(new PdfStream(
							IOUtils.toByteArray(getClass().getClassLoader().getResourceAsStream("HPARCA_CA.cer"))));
			document.close();
			pdfReader.close();

		} catch (IOException | GeneralSecurityException e) {
			LOG.error("Error while making signature ltv enabled");
		}
	}

	/**
	 *  Loops through certificates and adds them to the chain 
	 * @param ks The java keystore
	 * @return Chain of certificates located in java keystore
	 */
	private Certificate[] getCertificateChain(KeyStore ks) {
		Certificate[] chain = new java.security.cert.Certificate[numOfCertificates];
		try {
			Enumeration<String> al = ks.aliases();
			int count = 0;
			for (Enumeration<String> l = al; l.hasMoreElements();) {
				String alias = (String) l.nextElement();
				chain[count] = ks.getCertificate(alias);
				count++;
			}
		} catch (KeyStoreException e) {
			LOG.error("Error getting aliases from keystore", e);
		}

		return chain;
	}

	/**
	 *  Sets the properties of signature
	 *  
	 * @param signer The PDF signer
	 * @param certificationLevel
	 * @param name The signature field
	 */
	private void setSignProps(PdfSigner signer, int certificationLevel, String name) {
		signer.setCertificationLevel(certificationLevel);
		signer.setFieldName(name);
	}

	/**
	 * This method takes care of the appearance of the signature. You can also add watermark for example
	 * @param signer The PDFSigner so as to get the appearance
	 */
	private void setPdfSignatureAppearance(PdfSigner signer) {
		String reason = "";
		String location = "";
		boolean setReuseAppearance = false;
		PdfSignatureAppearance appearance = signer.getSignatureAppearance().setReason(reason).setLocation(location)
				.setReuseAppearance(setReuseAppearance);
		appearance.setLayer2Text("Digitally signed by me!\nDate: ");
		appearance.setLayer2FontSize(5.5f);
	}

	/**
	 * 
	 * @param source The source of pdf that will be encrypted
	 * @param target The outputstream that the encrypted stream will be written
	 * @param password The owner password of pdf to encrypt
	 * @throws IOException
	 */
	void encrypt(InputStream source, OutputStream target, byte[] password) throws IOException {
		PdfReader reader = new PdfReader(source);
		PdfWriter writer = new PdfWriter(target,
				new WriterProperties().setStandardEncryption(null, password, EncryptionConstants.ALLOW_PRINTING,
						EncryptionConstants.ENCRYPTION_AES_256 | EncryptionConstants.DO_NOT_ENCRYPT_METADATA));
		new PdfDocument(reader, writer).close();
	}

	/**
	 * 
	 * @return Returns the java keystore
	 */
	private KeyStore getKeyStore() {
		KeyStore ks = null;
		try {
			ks = KeyStore.getInstance(KeyStore.getDefaultType());
			ks.load(this.getClass().getClassLoader().getResourceAsStream(keystore), keystorePassword.toCharArray());
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			LOG.error("Error while loading keystore ", e);
		}
		return ks;
	}

}
