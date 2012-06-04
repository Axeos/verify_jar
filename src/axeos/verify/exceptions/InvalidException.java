package axeos.verify.exceptions;

public class InvalidException extends ValidatorException {

	private static final long serialVersionUID = 1L;

	public InvalidException() {
		super(5, "invalid", null);
	}

}
