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

import net.ukuehn.util.Base64;



public class HttpProxySocketInitialiser extends SocketInitialiser {

	static final int defaultPort = 8080;
	String crlf = "\r\n";

	String proxyHost;
	int proxyPort = defaultPort;

	private int timeout;

	boolean authRequired;

	String authID;
	String authPW;
	String authenticator; 


	public HttpProxySocketInitialiser() {
		authRequired = false;
		timeout = defaultTimeout;
	}


	public HttpProxySocketInitialiser(SocketInitialiser sockInit) {
		super(sockInit);
		authRequired = false;
		timeout = defaultTimeout;
	}


	public HttpProxySocketInitialiser(String host, int port) {
		proxyHost = host;
		proxyPort = port;
		authRequired = false;
		timeout = defaultTimeout;
	}


	public HttpProxySocketInitialiser(String host, int port,
					  SocketInitialiser sockInit) {
		super(sockInit);
		proxyHost = host;
		proxyPort = port;
		authRequired = false;
		timeout = defaultTimeout;
	}


	public void setProxy(String host, int port) {
		proxyHost = host;
		proxyPort = port;
	}


	public void setCredentials(String uid, String pass) {
		authID = uid;
		authPW = pass;
		if (Debug.get(Debug.SockInit)) {
			System.err.println("HttpProxySocketInitialiser: "
					   +" uid "+authID+" pw "+authPW);
		}
	}


	public Socket createSocket(String host, int port)
		throws IOException, FingerprintException, FingerprintError {

		Socket s = new Socket();
		s.connect(new InetSocketAddress(proxyHost, proxyPort),
			  1000*timeout);

		PrintWriter out = new PrintWriter(s.getOutputStream());
		InputStreamReader isr
			= new InputStreamReader(s.getInputStream());
		BufferedReader in = new BufferedReader(isr);

		String[] connHdr = {
			"CONNECT "+host+":"+port+" HTTP/1.1",
			"Host: "+host+":"+port,
			"Proxy-Connection: close"
		};

		String[] connReq = null;

		if (authRequired) {
			connReq = new String[connHdr.length+1];
			for (int i = 0;  i < connHdr.length;  i++) {
				connReq[i] = connHdr[i];
			}
			connReq[connHdr.length] =
				"Proxy-Authorization: "+authenticator;
		} else {
			connReq = new String[connHdr.length];
			for (int i = 0;  i < connHdr.length;  i++) {
				connReq[i] = connHdr[i];
			}
		}
		sendRequest(out, connReq);

		HttpResponseHeader hdr = new HttpResponseHeader(in);
		int status = hdr.getStatusCode();

		if (Debug.get(Debug.Communication)) {
			System.err.println("Got status "+status);
		}

		/* Now check the status code and act upon it */
		if ((status / 100) == 2) {  // Code is 2xx
			return s;
		}

		if ( ((status / 100) == 4)
		     && (status != 407) ) {
			throw new HttpProxyError("Proxy request failed");
		}

		if ((status == 407) && authRequired) {
			/* We already sent authorisation info,
			 * but the proxy did not accept it.
			 * So we can only stop here, as
			 * we do not have the right credentials
			 * at hand.
			 */
			throw new HttpProxyError("Cannot authenticate "
						 +"to proxy, wrong "
						 +"credentials?");
		}
		if (status == 407) {
			if (Debug.get(Debug.SockInit)) {
				System.err.println("Preparing proxy "
						   +"authenticator for "
						   +hdr.getProxyAuthInfo());
			}
			prepareAuthorisation(hdr.getProxyAuthInfo());
			authRequired = true;
			return createSocket(host, port);
		}
		return s;
	}


	public void initSocket(Socket s) {
	}


	protected void sendRequest(PrintWriter out, String[] msg) {
		for (int i = 0;  i < msg.length;  i++) {
			if (Debug.get(Debug.Communication)) {
				System.err.println(">>>" + msg[i]);
			}
			out.print(msg[i]+crlf);
		}
		if (Debug.get(Debug.Communication)) {
			System.err.println(">>>");
		}
		out.print(crlf);
		out.flush();
	}


	protected void prepareAuthorisation(String authVal)
		throws FingerprintError {

		if (authVal == null) {
			throw new HttpProxyError("Authentication "
						   +"challenge missing");
		}
		int idx = authVal.indexOf(' ');
		String scheme = authVal.substring(0,idx).toLowerCase();
		String param;
		if (authVal.length() > idx) {
			param = authVal.substring(idx+1);
		} else {
			param = "";
		}
		if (!scheme.equals("basic")) {
			throw new HttpProxyError("Auth scheme '"+scheme
						   +"' not supported");
		}
		if (Debug.get(Debug.SockInit)) {
			System.err.println("prepareAuthorisation: "
					   +"using scheme "+scheme);
		}
		authenticator = "Basic "+Base64.encode(authID+":"+authPW);
		if (Debug.get(Debug.SockInit)) {
			System.err.println("prepareAuthorisation: auth="
					   +authenticator);
		}
	}


	public int getDefaultPort() {
		return defaultPort;
	}


	public String getName() {
		return "HTTP Proxy (Connect)";
	}


}
