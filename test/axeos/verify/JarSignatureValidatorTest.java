package axeos.verify;

import java.util.jar.JarFile;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import axeos.verify.JarSignatureValidator.Result;

public class JarSignatureValidatorTest {

	private JarSignatureValidator jv;

	@Before
	public void init() {
		jv = new JarSignatureValidator();
	}

	@Test
	public void testVerifyJar() throws Exception {
		jv.setTrustedKeystore("./test/trustedKeystore.jks");

		Assert.assertEquals(Result.notSigned, jv.verifyJar(new JarFile("./test/sample_unsigned.jar")));

		Assert.assertEquals(Result.invalidSignature, jv.verifyJar(new JarFile("./test/sample_signed_self_invalid_error.jar")));
		Assert.assertEquals(Result.invalidSignature, jv.verifyJar(new JarFile("./test/sample_signed_self_invalid_sfmod_1.jar")));
		Assert.assertEquals(Result.invalidSignature, jv.verifyJar(new JarFile("./test/sample_signed_self_invalid_sfmod_2.jar")));
	}

	@Test
	public void testVerifyJar1() throws Exception {
		Assert.assertEquals(Result.invalidCertificate, jv.verifyJar(new JarFile("./test/sample_signed_self_tsa.jar")));
	}

	@Test
	public void testVerifyJar2() throws Exception {
		jv.setSkipCertUsage(true);

		Assert.assertEquals(Result.verified, jv.verifyJar(new JarFile("./test/sample_signed_self_tsa.jar")));
		Assert.assertEquals(Result.verified, jv.verifyJar(new JarFile("./test/sample_signed_self.jar")));
		Assert.assertEquals(Result.hasUnsignedEntries, jv.verifyJar(new JarFile("./test/sample_signed_self_invalid_1.jar")));
	}

}
