
verify_jar - command line JAR signature verification tool
=========================================================

JAR files with Java classes, or anything else, can be digitally signed to
assure their authenticity and integrity. Signing JARs is easy, just use
the __jarsigner__ utility that comes with JDK. Verification of the signatures
is more tricky, though. This little tool is supposed to help.

jarsigner limitations
---------------------

__jarsigner__ does provide a verification function, but it is quite useless
for a real-life and automated signature verifications.

The problems with `jarsigner -verify` include:

* No reliable status reporting. If no problems are found __jarsigner__ will
  print `verified` and exit with return code 0. If any problems are found
  it will print some error or warning messages __and__ the `verified` string
  and will also return code 0. No way to use it reliably in a script.

* It does not check signer certificate against trusted CAs. Any, untrusted
  signer certificate will do. So, __jarsigner__ actually can only check
  file integrity and not its authenticity.

* Although __jarsigner__ can add a trusted timestamp when signing a file,
  it never verifies it, so valid signatures cannot be properly verified
  after the signer certificate expires.

verify_jar usage
----------------

First compile the tool with **ant**, a moment later you can use it (you will
find it in the `target/` subdirectory).

Calling `verify_jar` with no arguments will show its usage description.

To verify a JAR with the JDK default trust store just invoke:

    verify_jar file.jar

Often one would like to check a JAR signature against own trusted CA. To do
that create a Java keystore file with your CA certificates using the
**keytool** utility and pass it to the **verify_jar** command using the
`-trusted-keystore` option:

    verify_jar -trusted-keystore mykeystore.jks file.jar

On success the utility will print `valid` to _stdout_ and exit with status 0.
When the signature verification fails or other error occurs `verifi_jar` will
print short result string to _stdout_, error messages to _stderr_ and exit
with non-zero status.

Possible exit status values and result strings:

* 0 – `valid`
* 1 – `unsigned entries`
* 2 - `not trusted`
* 3 – `expired`
* 4 - `not signed`
* 5 - `invalid`
* 6 – `error`

Please note, that only the first error detected is reported this way. And the
result of `expired` does not mean the signature is otherwise ok.

Copyright and license
---------------------

The code is distributed on the GPL version 2 license with the 'CLASSPATH'
exception for all but the main class. The license and the exception text
are provided in the LICENSE file.

As the code is inspired by the __jarsigner__ utility sources from the JDK,
us distributed by Oracle, under the same license, some minor fragments of the
code may be the same, so Oracle copyright may also apply.
