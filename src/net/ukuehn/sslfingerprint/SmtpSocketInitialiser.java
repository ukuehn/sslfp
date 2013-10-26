/* -*- java -*-
 *
 * This is sslfingerprint, an fingerprinting and security analysis tool
 * for server ssl configurations.
 *
 * (C) 2010 Ulrich Kuehn <ukuehn@acm.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 */

package net.ukuehn.sslfingerprint;



import javax.security.cert.*;
import javax.net.*;
import java.net.*;
import java.io.*;
import javax.net.ssl.*;


public class SmtpSocketInitialiser extends SocketInitialiser {

	static final int defaultPort = 587;
	String helloMessage = "EHLO sslanalyser";
	String crlf = "\r\n";
	String startTlsCmd = "STARTTLS";
	private int timeout;


	public SmtpSocketInitialiser() {
		timeout = defaultTimeout;
	}


	public SmtpSocketInitialiser(SocketInitialiser sockInit) {
		super(sockInit);
		timeout = defaultTimeout;
	}


	public Socket createSocket(String host, int port)
		throws IOException, FingerprintException, FingerprintError {

		Socket s;

		if (chainedInit != null) {
			s = chainedInit.createSocket(host, port);
		} else {
			//SocketFactory f = SocketFactory.getDefault();
			//s = (Socket)f.createSocket(host, port);
			s = new Socket();
			s.connect(new InetSocketAddress(host, port),
				  1000*timeout);
		}
		startTLSwithSmtp(s);
		return s;
	}


	public void initSocket(Socket s)
		throws IOException, FingerprintException, FingerprintError {

		if (chainedInit != null) {
			chainedInit.initSocket(s);
		}
		startTLSwithSmtp(s);
	}


	protected void startTLSwithSmtp(Socket s)
		throws IOException, NoStartTlsException {

		String line;
		boolean hasStartTLS;
		InputStreamReader isr
			= new InputStreamReader(s.getInputStream());
		BufferedReader in = new BufferedReader(isr);
		PrintWriter out = new PrintWriter(s.getOutputStream());

		line = in.readLine();
		if (Debug.get(Debug.Communication)) {
			System.err.println("<<<" + line);
		}
		if ((answerCode(line) != 220) || (line.indexOf("ESMTP") < 0)) {
			throw new NoStartTlsException(LocMsg.pr("e_no_esmtp"));
		}

		/* Send EHLO message and parse answer: look for
		 * starttls support
		 */
		sendCommand(out, helloMessage);
		hasStartTLS = false;
		do {
			line = in.readLine();
			if (Debug.get(Debug.Communication)) {
				System.err.println("<<<" + line);
			}
			if (answerCode(line) != 250) {
				throw new NoStartTlsException(
					   LocMsg.pr("e_smtp_failed"));
			}
			if (line.indexOf(startTlsCmd) >= 0) {
				hasStartTLS = true;
			}
		} while (answerContinued(line));

		if (!hasStartTLS) {
			throw new NoStartTlsException(
				    LocMsg.pr("e_no_starttls"));
		}

		sendCommand(out, startTlsCmd);
		line = in.readLine();
		if (answerCode(line) != 220) {
			throw new NoStartTlsException(
			     LocMsg.pr("e_starttls_code",
					   String.valueOf(answerCode(line)))
			     );
		}
		/* We are ready here to start TLS conversation */
	}


	protected int answerCode(String line) {
		if (line == null) {
			return -1;
		}
		if (line.length() < 4) {
			return -1;
		}
		try {
			return Integer.parseInt(line.substring(0,3));
		} catch (NumberFormatException e) {
			// Any result != 250 will trigger a
			// NoStartTlsException in caller
			return -2;
		}
	}


	protected boolean answerContinued(String line) {
		if (line == null) {
			return false;
		}
		if (line.length() < 5) {
			return false;
		}
		return (line.charAt(3) == '-');
	}


	protected void sendCommand(PrintWriter out, String msg) {
		if (Debug.get(Debug.Communication)) {
			System.err.println(">>>" + msg);
		}
		out.print(msg+crlf);
		out.flush();
	}


	public int getDefaultPort() {
		return defaultPort;
	}


	public String getName() {
		return "SMTP (StartTLS)";
	}


}