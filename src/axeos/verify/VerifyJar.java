/*
 * Copyright (c) 2012, Axeos B.V, and contributors
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */
package axeos.verify;

import java.net.URL;
import java.net.URLClassLoader;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.logging.ConsoleHandler;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import axeos.verify.exceptions.ValidatorException;

public class VerifyJar {

	private static class MyFormatter extends Formatter {

		private final DateFormat df = new SimpleDateFormat("dd/MM/yyyy hh:mm:ss.SSS");

		@Override
		public String format(LogRecord record) {
			StringBuilder builder = new StringBuilder(1000);
			builder.append(df.format(new Date(record.getMillis()))).append(" - ");
			builder.append("[").append(record.getSourceClassName()).append(".");
			builder.append(record.getSourceMethodName()).append("] - ");
			builder.append("[").append(record.getLevel()).append("] - ");
			builder.append(formatMessage(record));
			builder.append("\n");
			if (record.getThrown() != null) {
				builder.append(" Exception! " + record.getThrown().getMessage());
			}
			return builder.toString();
		}

		@Override
		public String getHead(Handler h) {
			return super.getHead(h);
		}

		@Override
		public String getTail(Handler h) {
			return super.getTail(h);
		}
	}

	public static final String VERIFIED = "valid";

	private static String getBuildDate() {
		try {
			URLClassLoader cl = (URLClassLoader) VerifyJar.class.getClassLoader();
			URL url = cl.findResource("META-INF/MANIFEST.MF");
			Manifest manifest = new Manifest(url.openStream());
			return manifest.getMainAttributes().getValue("Built-Date");
		} catch (Exception e) {
			return null;
		}
	}

	private static String getVersion() {
		String version = VerifyJar.class.getPackage().getImplementationVersion();
		return version == null ? "0.0.0" : version;
	}

	public static void main(String[] args) throws Exception {
		VerifyJar v = new VerifyJar();
		v.parseParameters(args);
		if (v.file == null) {
			showHelp();
			System.exit(-1);
		}
		v.run();
	}

	private static void showHelp() {
		String dt = getBuildDate();
		System.err.println("Axeos Jar Verifier " + getVersion() + (dt == null ? "" : (" (" + dt + ")")));
		System.err.println("Usage:");
		System.err.println("   verify_jar <parameters> <jar_file>");
		System.err.println("Parameters:");
		System.err.println("  -trusted-keystore <file>  :  keystore with trusted CA certificates");
		System.err.println("  -ocsp  :  use OCSP for certificate verification");
		System.err.println("  -ocsp-responder <url>  :  OCSP responder to use (default: from the signer's certificate)");
		System.err.println("  -crl <file>  :  certificate revocation list file");
		System.err.println("  -skip-key-usage  :  do not check key usage attributes on the signer certificate");
		System.err.println("  -quiet  :  write nothing to stdout and limit warning messages");
		System.err.println("  -skip-trust-check  :  skip certificate trust check");
		System.err.println("  -time <time>  :  check signature validity at the given point in time (yyyy-MM-dd[ HH:mm[:ss[.S]]])");
		System.err.println("  -debug  :  print debug information");
	}

	private String file;

	private final JarSignatureValidator jv = new JarSignatureValidator();

	private boolean quiet = false;

	private Date parseDate(String d) {
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.S");
		try {
			return sdf.parse(d);
		} catch (Exception e) {
		}
		sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		try {
			return sdf.parse(d);
		} catch (Exception e) {
		}
		sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm");
		try {
			return sdf.parse(d);
		} catch (Exception e) {
		}
		sdf = new SimpleDateFormat("yyyy-MM-dd");
		try {
			return sdf.parse(d);
		} catch (Exception e) {
		}
		return null;
	}

	private void parseParameters(String[] args) {
		for (int i = 0; i < args.length; i++) {
			String par = args[i];
			if ("-skip-trust-check".equalsIgnoreCase(par)) {
				jv.setSkipTrustCheck(true);
			} else if ("-date".equalsIgnoreCase(par)) {
				String d = args[++i];
				if (i + 1 < args.length && !args[i + 1].startsWith("-")) {
					d += " " + args[++i];
				}
				jv.setVerificationDate(parseDate(d));
			} else if ("-quiet".equalsIgnoreCase(par)) {
				quiet = true;
				jv.setQuiet(quiet);
			} else if ("-debug".equalsIgnoreCase(par)) {
				Logger logger = Logger.getLogger("");
				Handler handler = new ConsoleHandler();
				handler.setFormatter(new MyFormatter());
				handler.setLevel(Level.ALL);
				logger.addHandler(handler);
				logger.setLevel(Level.ALL);
			} else if ("-trusted-keystore".equalsIgnoreCase(par)) {
				jv.setTrustedKeystore(args[++i]);
			} else if ("-ocsp".equalsIgnoreCase(par)) {
				jv.setUseOCSP(true);
			} else if ("-ocsp-responder".equalsIgnoreCase(par)) {
				jv.setUseOCSP(true);
				jv.setOcspResponderURL(args[++i]);
			} else if ("-crl".equalsIgnoreCase(par)) {
				jv.getCrlFileNames().add(args[++i]);
			} else if ("-skip-key-usage".equalsIgnoreCase(par)) {
				jv.setSkipCertUsage(true);
			} else if (file == null && !par.startsWith("-")) {
				file = par;
			} else {
				System.err.println("Unkown command '" + par + "'");
				showHelp();
				System.exit(255);
			}
		}
	}

	private void run() {
		try {
			jv.verifyJar(new JarFile(file));
			if (!quiet) {
				System.out.println("valid");
			}
			System.exit(0);
		} catch (ValidatorException e) {
			String errMsg = e.getStdErrMessage();
			String outMsg = e.getStdOutMessage();
			int code = e.getExitCode();

			if (!quiet && outMsg != null)
				System.out.println(outMsg);
			if (errMsg != null)
				System.err.println(errMsg);
			System.exit(code);
		} catch (Throwable e) {
			e.printStackTrace();
			if (!quiet) {
				System.out.println("error");
			}
			System.exit(6);
		}
	}
}
