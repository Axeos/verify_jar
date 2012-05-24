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
		// handler.setFormatter(new MyFormatter());
		handler.setLevel(Level.ALL);
		logger.addHandler(handler);
		logger.setLevel(Level.ALL);

		JarSignatureValidator jv = new JarSignatureValidator();

		// jv.verifyJar(new JarFile("./test/sample_signed_self_invalid_1.jar"));
		// jv.verifyJar(new
		// JarFile("./test/sample_signed_self_invalid_sfmod_2.jar"));
		System.out.println(jv.verifyJar(new JarFile("./test/sample_signed_self.jar")));
		System.out.println(jv.verifyJar(new JarFile("./test/sample_unsigned.jar")));
	}

}
