package axeos.verify.exceptions;

public abstract class ValidatorException extends Exception {

	private static final long serialVersionUID = 1L;

	private final int exitCode;

	private final String stdErrMessage;

	private final String stdOutMessage;

	protected ValidatorException(int exitCode, String stdOutMessage, String stdErrMessage) {
		super();
		this.exitCode = exitCode;
		this.stdOutMessage = stdOutMessage;
		this.stdErrMessage = stdErrMessage;
	}

	public int getExitCode() {
		return exitCode;
	}

	public String getStdErrMessage() {
		return stdErrMessage;
	}

	public String getStdOutMessage() {
		return stdOutMessage;
	}

}
