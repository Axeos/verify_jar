package axeos.verify;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.jar.JarFile;
import java.util.logging.ConsoleHandler;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import axeos.verify.JarSignatureValidator.Result;

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

	public static void main(String[] args) throws Exception {
		Logger logger = Logger.getLogger("");
		Handler handler = new ConsoleHandler();
		handler.setFormatter(new MyFormatter());
		handler.setLevel(Level.ALL);
		logger.addHandler(handler);
		logger.setLevel(Level.ALL);

		VerifyJar v = new VerifyJar();
		v.parseParameters(args);
		v.run();

		// JarSignatureValidator jv = new JarSignatureValidator();

		// jv.verifyJar(new JarFile("./test/sample_signed_self_invalid_1.jar"));
		// jv.verifyJar(new
		// JarFile("./test/sample_signed_self_invalid_sfmod_2.jar"));
		// System.out.println(jv.verifyJar(new
		// JarFile("./test/sample_signed_self.jar")));
		// System.out.println(jv.verifyJar(new
		// JarFile("./test/sample_unsigned.jar")));
	}

	private String file;

	private final JarSignatureValidator jv = new JarSignatureValidator();

	private final Logger log = Logger.getLogger(VerifyJar.class.getName());

	private void parseParameters(String[] args) {
		for (int i = 0; i < args.length; i++) {
			String par = args[i];
			if ("-trustedKeystore".equalsIgnoreCase(par)) {
				jv.setTrustedKeystore(args[++i]);
			} else if ("-ocsp".equalsIgnoreCase(par)) {
				jv.setUseOCSP(true);
			} else if ("-ocspResponder".equalsIgnoreCase(par)) {
				jv.setUseOCSP(true);
				jv.setOcspResponderURL(args[++i]);
			} else if ("-crl".equalsIgnoreCase(par)) {
				jv.getCrlFileNames().add(args[++i]);
			} else if ("-skipUsage".equalsIgnoreCase(par)) {
				jv.setSkipCertUsage(true);
			} else if (file == null) {
				file = par;
			} else {
				// throw new RuntimeException("Unknown parameter");
			}
		}
	}

	private void run() {
		try {
			Result res = jv.verifyJar(new JarFile(file));

			switch (res) {
			case verified:
				System.exit(0);
				break;
			case expiredCertificate:
				System.exit(1);
				break;
			default:
				System.exit(2);
				break;
			}

		} catch (Throwable e) {
			e.printStackTrace();
			System.exit(2);
		}
	}
}
