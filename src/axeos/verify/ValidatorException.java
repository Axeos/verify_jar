package axeos.verify;

import axeos.verify.JarSignatureValidator.Result;

public class ValidatorException extends Exception {

	private static final long serialVersionUID = 1L;

	private final int exitCode;

	private final Result result;

	private final String stdErrMessage;

	private final String stdOutMessage;

	public ValidatorException(Result result) {
		this(result, -1, null, null);
	}

	public ValidatorException(Result result, int exitCode, String stdOutMessage, String stdErrMessage) {
		super();
		this.result = result;
		this.exitCode = exitCode;
		this.stdOutMessage = stdOutMessage;
		this.stdErrMessage = stdErrMessage;
	}

	public ValidatorException(Result result, String stdOutMessage, String stdErrMessage) {
		this(result, -1, stdOutMessage, stdErrMessage);
	}

	public int getExitCode() {
		return exitCode;
	}

	public Result getResult() {
		return result;
	}

	public String getStdErrMessage() {
		return stdErrMessage;
	}

	public String getStdOutMessage() {
		return stdOutMessage;
	}

}
