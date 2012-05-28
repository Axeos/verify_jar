package axeos.verify;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.CodeSigner;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.Timestamp;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.logging.Level;
import java.util.logging.Logger;

public class JarSignatureValidator {

	public static enum Result {
		expiredCertificate,
		hasUnsignedEntries,
		invalidCertificate,
		invalidSignature,
		notSigned,
		verified

	}

	private final List<String> crlFileNames = new ArrayList<String>();

	private final Logger log = Logger.getLogger(JarSignatureValidator.class.getName());

	private String ocspResponderURL;

	private PKIXParameters params;

	private boolean skipCertUsage = false;

	private String trustedKeystore;

	private boolean useOCSP;

	private CertPathValidator validator;

	public List<String> getCrlFileNames() {
		return crlFileNames;
	}

	public String getOcspResponderURL() {
		return ocspResponderURL;
	}

	public String getTrustedKeystore() {
		return trustedKeystore;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	private void initPathValdiator() throws NoSuchAlgorithmException, KeyStoreException, CertificateException,
			FileNotFoundException, IOException, InvalidAlgorithmParameterException, CRLException {
		if (trustedKeystore == null) {
			log.fine("  No trusted keystore. Certificate path validation skiped.");
			this.validator = null;
			return;
		}

		Security.setProperty("ocsp.enable", useOCSP ? "true" : "false");
		if (ocspResponderURL != null)
			Security.setProperty("ocsp.responderURL", ocspResponderURL);

		CertPathValidator validator = CertPathValidator.getInstance("PKIX");

		KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());

		keystore.load(new FileInputStream(trustedKeystore), null);

		this.params = new PKIXParameters(keystore);

		List l = new ArrayList();

		params.setRevocationEnabled(useOCSP || crlFileNames != null && !crlFileNames.isEmpty());

		if (crlFileNames != null) {
			for (String crlFile : crlFileNames) {
				l.addAll(CertificateFactory.getInstance("X.509").generateCRLs(new FileInputStream(crlFile)));
			}
		}

		CollectionCertStoreParameters csParams = new CollectionCertStoreParameters(l);

		CertStore certStore = CertStore.getInstance("Collection", csParams);

		params.addCertStore(certStore);

		this.validator = validator;
	}

	private boolean isCertForCodeSigning(final X509Certificate cert) throws CertificateParsingException {
		List<String> extUsage = cert.getExtendedKeyUsage();
		// 2.5.29.37.0 - Any extended key usage
		// 1.3.6.1.5.5.7.3.3 - Code Signing
		return extUsage != null && (extUsage.contains("2.5.29.37.0") || extUsage.contains("1.3.6.1.5.5.7.3.3"));
	}

	private boolean isSignatureRelatedFilename(String filename) {
		String tmp = filename.toUpperCase();
		if (tmp.equals(JarFile.MANIFEST_NAME) || tmp.equals("META-INF/")
				|| (tmp.startsWith("META-INF/SIG-") && tmp.indexOf("/") == tmp.lastIndexOf("/"))) {
			return true;
		}
		if (tmp.startsWith("META-INF/") && (tmp.endsWith(".SF") || tmp.endsWith(".DSA") || tmp.endsWith(".RSA"))) {
			return (tmp.indexOf("/") == tmp.lastIndexOf("/"));
		}

		return false;
	}

	public boolean isSkipCertUsage() {
		return skipCertUsage;
	}

	public boolean isUseOCSP() {
		return useOCSP;
	}

	public void setOcspResponderURL(String ocspResponderURL) {
		this.ocspResponderURL = ocspResponderURL;
	}

	public void setSkipCertUsage(boolean skipCertUsage) {
		this.skipCertUsage = skipCertUsage;
	}

	public void setTrustedKeystore(String trustedKeystore) {
		this.trustedKeystore = trustedKeystore;
	}

	public void setUseOCSP(boolean useOCSP) {
		this.useOCSP = useOCSP;
	}

	private void validatePath(CertPath path) throws NoSuchAlgorithmException, KeyStoreException,
			InvalidAlgorithmParameterException, CertPathValidatorException, CRLException, CertificateException, IOException {

		if (validator == null) {
			return;
		}

		PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) validator.validate(path, params);
		if (result == null)
			throw new RuntimeException("No result???");

		if (log.isLoggable(Level.FINEST)) {
			log.finest("  path valid");
		}
	}

	public Result verifyJar(final JarFile jarFile) throws IOException, KeyStoreException, CertificateException,
			NoSuchAlgorithmException, InvalidAlgorithmParameterException, CertPathValidatorException, CRLException {
		byte[] buffer = new byte[8192];

		boolean anySigned = false;
		boolean hasUnsignedEntry = false;
		boolean hasExpiredCert = false;

		initPathValdiator();
		// -------

		// -------

		final Manifest manifest = jarFile.getManifest();

		final ArrayList<JarEntry> entries = new ArrayList<JarEntry>();

		Enumeration<JarEntry> entriesEnum = jarFile.entries();
		while (entriesEnum.hasMoreElements()) {
			JarEntry entry = entriesEnum.nextElement();
			entries.add(entry);
			InputStream is = null;

			if (log.isLoggable(Level.FINEST))
				log.finest("Checking file " + entry);
			try {
				is = jarFile.getInputStream(entry);
				// Checking SHA-1
				while ((is.read(buffer, 0, buffer.length)) != -1)
					;
			} catch (java.lang.SecurityException e) {
				if (log.isLoggable(Level.FINEST))
					log.log(Level.FINEST, "  Invalid signature!!!", e);
				return Result.invalidSignature;
			} finally {
				if (is != null) {
					is.close();
				}
			}

			String name = entry.getName();
			CodeSigner[] codeSigners = entry.getCodeSigners();

			boolean isSigned = (codeSigners != null);
			boolean inManifest = ((manifest.getAttributes(name) != null) || (manifest.getAttributes("./" + name) != null) || (manifest.getAttributes("/"
					+ name) != null));
			anySigned |= isSigned;
			hasUnsignedEntry |= !entry.isDirectory() && !isSigned && !isSignatureRelatedFilename(name);

			if (log.isLoggable(Level.FINEST)) {
				log.finest("  " + (isSigned ? "signed" : "      ") + "  " + (inManifest ? "manifest" : "        ") + "  ");
			}

			if (isSigned) {
				for (int i = 0; i < codeSigners.length; i++) {
					Certificate cert = codeSigners[i].getSignerCertPath().getCertificates().get(0);
					Timestamp timestamp = codeSigners[i].getTimestamp();
					if (timestamp != null) {
						log.finer("  Found timestamp.");
						CertPath cp = timestamp.getSignerCertPath();
						try {
							log.finer("  Validating timestamp certificate path");
							validatePath(cp);
						} catch (Exception e) {
							log.fine("Timestamp certificate is not valid");
							return Result.invalidSignature;
						}
					}

					List<Certificate> x = new ArrayList<Certificate>();
					for (Certificate c : codeSigners[i].getSignerCertPath().getCertificates()) {
						x.add(c);
					}
					CertPath path = CertificateFactory.getInstance("X.509").generateCertPath(x);

					try {
						validatePath(path);
					} catch (Exception e) {
						log.fine("Certificate path can't be verified!");
						return Result.invalidCertificate;
					}

					if (cert instanceof X509Certificate) {

						if (log.isLoggable(Level.FINEST)) {
							log.finest("  Used certificate  SerialNumber: " + ((X509Certificate) cert).getSerialNumber()
									+ "; Subject: " + ((X509Certificate) cert).getSubjectDN());
						}
						boolean correctUsage = isCertForCodeSigning((X509Certificate) cert);// TODO

						if (!skipCertUsage && !correctUsage) {
							log.fine("Certificate can't be used to signing code");
							return Result.invalidCertificate;
						}

						try {
							if (timestamp != null)
								((X509Certificate) cert).checkValidity(timestamp.getTimestamp());
							else
								((X509Certificate) cert).checkValidity();
						} catch (CertificateNotYetValidException e) {
							hasExpiredCert = true;
						} catch (CertificateExpiredException e) {
							hasExpiredCert = true;
						}

						if (hasExpiredCert) {
							log.fine("Certificate is expired");
							return Result.expiredCertificate;
						}

						if (log.isLoggable(Level.FINEST)) {
							log.finest("  usage: " + (correctUsage ? "correct" : "incorrect") + "; expired: " + hasExpiredCert
									+ ";");
						}
					}
				}
			}

		}

		if (!anySigned) {
			if (log.isLoggable(Level.FINE))
				log.fine("File is not signed");
			return Result.notSigned;
		} else if (hasUnsignedEntry) {
			if (log.isLoggable(Level.FINE))
				log.fine("File contains unsigned entries!");
			return Result.hasUnsignedEntries;
		}

		if (log.isLoggable(Level.FINE))
			log.fine("File verified");
		return Result.verified;
	}

}
