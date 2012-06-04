package axeos.verify.exceptions;

public class ExpiredException extends ValidatorException {

	private static final long serialVersionUID = 1L;

	public ExpiredException() {
		super(3, "expired", "Signer certificate expired");
	}

}
