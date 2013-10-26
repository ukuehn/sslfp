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

import java.text.NumberFormat;
import java.util.StringTokenizer;


public class ImapSocketInitialiser extends SocketInitialiser {

	static final int defaultPort = 143;
	static final String CRLF = "\r\n";
	static final String CMDCAP = "CAPABILITY";
	static final String CMDSTARTTLS = "STARTTLS";
	static final String REPOK = "OK";
	static final String REPCONT = "*";

	static final String TAGSTART = "A";
	static final String TAGSEP = " ";
	protected long tagCount;
	protected NumberFormat tnf;
	
	private int timeout;

	public ImapSocketInitialiser() {
		timeout = defaultTimeout;
		tagCount = 0;
		tnf = NumberFormat.getIntegerInstance();
		tnf.setMinimumIntegerDigits(4);
		tnf.setGroupingUsed(false);
	}


	public ImapSocketInitialiser(SocketInitialiser sockInit) {
		super(sockInit);
		timeout = defaultTimeout;
		tagCount = 0;
		tnf = NumberFormat.getIntegerInstance();
		tnf.setMinimumIntegerDigits(4);
		tnf.setGroupingUsed(false);
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
		startTLSwithImap(s);
		return s;
	}


	public void initSocket(Socket s)
		throws IOException, FingerprintException, FingerprintError {

		if (chainedInit != null) {
			chainedInit.initSocket(s);
		}
		startTLSwithImap(s);
	}


	protected void startTLSwithImap(Socket s) 
		throws IOException, NoStartTlsException {

		String line;
		String capability = null;
		boolean hasStartTLS;
		InputStreamReader isr
			= new InputStreamReader(s.getInputStream());
		BufferedReader in = new BufferedReader(isr);
		PrintWriter out = new PrintWriter(s.getOutputStream());

		line = getReplyLine(in);
		if (!serverIsReady(line)) {
			throw new NoStartTlsException(LocMsg.pr("e_no_imap"));
		}

		capability = getCapaFromServerGreeting(line);
		if (capability == null) {
			sendCommand(out, CMDCAP);
			capability = getCapability(in);
		}

		if (Debug.get(Debug.Protocol)) {
			System.err.println("Got capability: "+capability);
		}
		if (capability == null) {
			throw new NoStartTlsException(
					    LocMsg.pr("e_no_imap_capa"));
		}
		String up = capability.toUpperCase();
		if (up.indexOf(CMDSTARTTLS) == -1) {
			throw new NoStartTlsException(
					  LocMsg.pr("e_no_starttls"));
		}

		sendCommand(out, CMDSTARTTLS);
		line = getReplyLine(in);
		if (!replyOK(line)) {
			throw new NoStartTlsException(
					  LocMsg.pr("e_starttls_failed"));
		}
		
		/* We are ready here to start TLS conversation */
	}


	protected boolean serverIsReady(String line) {
		String up = line.substring(0, 5).toUpperCase();
		return up.startsWith("* OK");
	}


	protected String getCapaFromServerGreeting(String line) {
		String res = null;
		String upLine = line.toUpperCase();
		if (line.startsWith("* OK [CAPABILITY")) {
			int start = line.indexOf('[');
			int end = line.indexOf(']', start);
			if (end < 0) {
				return null;
			}
			try {
				res = line.substring(start+1, end);
			} catch (IndexOutOfBoundsException e) {
				// ignore, res is already null
			}
		}
		return res;
	}


	protected String getCapability(BufferedReader in) throws IOException {

		String res = null;
		String line;

		for (line = getReplyLine(in);
		     replyInProgress(line);  
		     line = getReplyLine(in)) {
			String upLine = line.toUpperCase();
			if (upLine.startsWith("* CAPABILITY")) {
				res = line.substring(2);
			}
		}
		if (!replyOK(line)) {
			return null;
		}
		return res;
	}


	protected boolean replyInProgress(String line) {
		if (line == null) {
			return false;
		}
		return line.startsWith(REPCONT);
	}


	protected boolean replyOK(String line) {
		StringTokenizer st = new StringTokenizer(line, " ");
		String tag = st.nextToken();
		String res = st.nextToken();
		if (res == null) {
			return false;
		}
		return res.equalsIgnoreCase(REPOK);
	}


	protected void sendCommand(PrintWriter out, String msg) {
		String tag = TAGSTART+tnf.format(tagCount++);
		if (Debug.get(Debug.Communication)) {
			System.err.println(">>>" + tag + TAGSEP + msg);
		}
		out.print(tag+TAGSEP+msg+CRLF);
		out.flush();
	}


	protected String getReplyLine(BufferedReader in) throws IOException {
		String line = in.readLine();
		if (Debug.get(Debug.Communication)) {
			System.err.println("<<<" + line);
		}
		return line;
	}


	public int getDefaultPort() {
		return defaultPort;
	}


	public String getName() {
		return "IMAP (StartTLS) -- experimental";
	}

}
