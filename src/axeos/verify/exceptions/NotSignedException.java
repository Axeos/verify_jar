package axeos.verify.exceptions;

public class NotSignedException extends ValidatorException {

	private static final long serialVersionUID = 1L;

	public NotSignedException() {
		super(4, "not signed", null);
	}
}
