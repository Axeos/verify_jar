package axeos.verify;

import java.io.File;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.cert.CertificateParsingException;
import java.util.jar.JarFile;

import org.junit.Assert;
import org.junit.Test;

import axeos.verify.JarVerify.Result;

public class JarVerifyTest {

	@Test
	public void testVerifyJar() throws CertificateParsingException, KeyStoreException, IOException {
		JarVerify jv = new JarVerify();

		Assert.assertEquals(Result.verified, jv.verifyJar(new JarFile("./test/sample_signed_self_tsa.jar")));
		Assert.assertEquals(Result.verified, jv.verifyJar(new JarFile("./test/sample_signed_self.jar")));

		Assert.assertEquals(Result.notSigned, jv.verifyJar(new JarFile("./test/sample_unsigned.jar")));

		Assert.assertEquals(Result.hasUnsignedEntries, jv.verifyJar(new JarFile("./test/sample_signed_self_invalid_1.jar")));

		Assert.assertEquals(Result.invalidSignature, jv.verifyJar(new JarFile("./test/sample_signed_self_invalid_error.jar")));
		Assert.assertEquals(Result.invalidSignature, jv.verifyJar(new JarFile("./test/sample_signed_self_invalid_sfmod_1.jar")));
		Assert.assertEquals(Result.invalidSignature, jv.verifyJar(new JarFile("./test/sample_signed_self_invalid_sfmod_2.jar")));

	}

}
