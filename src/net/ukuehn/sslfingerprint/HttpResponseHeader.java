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


public class HttpResponseHeader {

	int statusCode;
	String statusPhrase;
	String httpVersion;
	int contentLength;
	String contentType;
	String proxyAuthInfo;
	boolean keepAlive;
	boolean proxyKeepAlive;


	public HttpResponseHeader() {
	}


	public HttpResponseHeader(BufferedReader in) throws IOException {
		parseResponseHeader(in);
	}


	public int getStatusCode() {
		return statusCode;
	}


	public String getStatusPhrase() {
		return statusPhrase;
	}


	public int getContentLength() {
		return contentLength;
	}


	public String getProxyAuthInfo() {
		return proxyAuthInfo;
	}


	protected void parseResponseHeader(BufferedReader in)
		throws IOException {

		String line;

		line = in.readLine();
		if (Debug.get(Debug.Communication)) {
			System.err.println("<<<"+line);
		}
		parseStatusLine(line);

		for (line = in.readLine();
		     line.length() > 0;  line = in.readLine()) {

			if (Debug.get(Debug.Communication)) {
				System.err.println("<<<"+line);
			}

		       	int sepIdx = line.indexOf(':');
			if (sepIdx < 0) {
				throw new
					ProtocolException("Wrong format in "
							  +"response header");
			}
			String tag = line.substring(0,sepIdx).toLowerCase();
			String value = line.substring(sepIdx+1).trim();

			if (Debug.get(Debug.Communication)) {
				System.err.println("   Tag "+tag
						   +", val "+value);
			}

			/* Check which header part this is:
			 * we understand Connection, Content-Type,
			 * Content-Length, Proxy-Authentication,
			 * Proxy-Connection
			 */
			switch (tag.charAt(0)) {
			case 'c' :
				if (tag.equals("connection")) {
					parseConnection(value);
				}
				break;
			case 'p' :
				if (tag.equals("proxy-authenticate")) {
					parseProxyAuthentication(value);
				} else if (tag.equals("proxy-connection")) {
					parseProxyConnection(value);
				}
			}
		}
	}


	/* HTTP response status line consists of
	 * http-version SP status-code SP Reason-phrase CRLF
	 * where SP is a single space character.
	 */
	protected void parseStatusLine(String line) throws IOException {
		String sCode;

		statusCode = 0;
		if (line == null) {
			throw new ProtocolException("Invalid response format");
		}
		int n = line.indexOf(' ');
		sCode = line.substring(n+1, n+1+3);
		if (sCode.length() != 3) {
			throw new IOException("Invalid responde code "+sCode);
		}
		try {
			statusCode = Integer.parseInt(sCode);
		} catch (NumberFormatException e) {
			throw new IOException("Invalid responde code "+sCode);
		}
		httpVersion = line.substring(0, n);
		statusPhrase = line.substring(n+1+3+1);
		if (Debug.get(Debug.Protocol)) {
			System.err.println("   httpversion '"+httpVersion
					   +"' code "+statusCode
					   +" phrase '"+statusPhrase+"'");
		}

	}


	private void parseConnection(String value) throws IOException {
		if (value.toLowerCase().equals("close")) {
			keepAlive = false;
		} else {
			keepAlive = true;
		}
	}


	private void parseProxyAuthentication(String value)
		throws IOException {
		if (proxyAuthInfo == null) {
			proxyAuthInfo = value;
		}
	}


	private void parseProxyConnection(String value)
		throws IOException {
		if (value.toLowerCase().equals("close")) {
			proxyKeepAlive = false;
		} else {
			proxyKeepAlive = true;
		}		
	}


	private void parseContentLength(String value) throws IOException {
		contentLength = 0;
	}



}
