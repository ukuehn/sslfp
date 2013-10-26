/* -*- java -*-
 *
 * This is sslfingerprint, an fingerprinting and security analysis tool
 * for server ssl configurations.
 *
 * (C) 2010, 2012 Ulrich Kuehn <ukuehn@acm.org>
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


public class Pop3SocketInitialiser extends SocketInitialiser {

	static final int defaultPort = 110;
	String crlf = "\r\n";
	String replyOK = "+OK";
	String capaCmd = "CAPA";
	String startTlsCmd = "STLS";
	
	private int timeout;


	public Pop3SocketInitialiser() {
		timeout = defaultTimeout;
	}


	public Pop3SocketInitialiser(SocketInitialiser sockInit) {
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
		startTLSwithPop3(s);
		return s;
	}


	public void initSocket(Socket s)
		throws IOException, FingerprintException, FingerprintError {

		if (chainedInit != null) {
			chainedInit.initSocket(s);
		}
		startTLSwithPop3(s);
	}


	protected void startTLSwithPop3(Socket s) 
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
		if (!line.startsWith(replyOK) && (line.indexOf("POP3") < 0)) {
			throw new NoStartTlsException(LocMsg.pr("e_no_pop3"));
		}

		/* Send CAPA command and parse answer: look for
		 * starttls support
		 */
		sendCommand(out, capaCmd);
		hasStartTLS = false;
		line = in.readLine();
		if (Debug.get(Debug.Communication)) {
			System.err.println("<<<" + line);
		}
		if (!line.startsWith(replyOK)) {
			throw new NoStartTlsException(
					 LocMsg.pr("e_capa_failed"));
		}
		do {
			line = in.readLine();
			if (Debug.get(Debug.Communication)) {
				System.err.println("<<<" + line);
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
		if (!line.startsWith(replyOK)) {
			throw new NoStartTlsException(
				       LocMsg.pr("e_starttls_failed"));
		}
		/* We are ready here to start TLS conversation */
	}


	protected boolean answerContinued(String line) {
		if (line == null) {
			return false;
		}
		return !line.equals(".");
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
		return "POP3 (StartTLS)";
	}

}
