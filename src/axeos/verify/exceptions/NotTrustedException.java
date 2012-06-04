package axeos.verify.exceptions;

public class NotTrustedException extends ValidatorException {

	private static final long serialVersionUID = 1L;

	public NotTrustedException() {
		super(2, "not trusted", null);
	}

}
