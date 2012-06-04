package axeos.verify.exceptions;

public class UnsignedEntriesException extends ValidatorException {

	private static final long serialVersionUID = 1L;

	public UnsignedEntriesException() {
		super(1, "unsigned entries", null);
	}

}
