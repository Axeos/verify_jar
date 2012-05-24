package axeos.verify;

import java.io.IOException;
import java.io.InputStream;
import java.security.CodeSigner;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
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
		hasUnsignedEntries,
		invalidSignature,
		notSigned,
		verified

	}

	private final Logger log = Logger.getLogger(JarSignatureValidator.class.getName());

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

	public Result verifyJar(final JarFile jarFile) throws IOException, KeyStoreException, CertificateParsingException {
		byte[] buffer = new byte[8192];

		boolean anySigned = false;
		boolean hasUnsignedEntry = false;
		boolean hasExpiredCert = false;

		// -------

		final long now = System.currentTimeMillis();

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
					if (cert instanceof X509Certificate) {
						if (log.isLoggable(Level.FINEST)) {
							log.finest("  Used certificate  SerialNumber: " + ((X509Certificate) cert).getSerialNumber()
									+ "; Subject: " + ((X509Certificate) cert).getSubjectDN());
						}
						boolean correctUsage = isCertForCodeSigning((X509Certificate) cert);// TODO
						long notAfter = ((X509Certificate) cert).getNotAfter().getTime();

						if (notAfter < now) {
							hasExpiredCert = true;
						}
						if (log.isLoggable(Level.FINEST)) {
							log.finest("  usage: " + (correctUsage ? "correct" : "incorrect") + "; expired: " + hasExpiredCert
									+ ";");
						}
					}
				}
			}

		}

		if (log.isLoggable(Level.FINE)) {
			log.fine("hasUnsignedEntry=" + hasUnsignedEntry);
			log.fine("anySigned=" + anySigned);
		}

		if (!anySigned) {
			return Result.notSigned;
		} else if (hasUnsignedEntry) {
			return Result.hasUnsignedEntries;
		}

		return Result.verified;
	}

}
