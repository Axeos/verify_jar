/*
 * Copyright (c) 2012, Axeos B.V, and contributors
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Axeos designates this
 * particular file as subject to the "Classpath" exception as provided
 * in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */
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
