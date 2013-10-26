/* -*- java -*-
 *
 * This is sslfingerprint, an fingerprinting and security analysis tool
 * for server ssl configurations.
 *
 * (C) 2010-2012 Ulrich Kuehn <ukuehn@acm.org>
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


import javax.net.ssl.*;
//import javax.security.cert.*;
import javax.security.auth.*;
import java.security.NoSuchAlgorithmException;
import javax.net.*;
import java.security.cert.*;
import java.net.*;
import java.io.*;

import java.util.Set;
import java.util.LinkedHashSet;
import java.util.Iterator;

	
public class SSLv2ConfigCollector {

	final byte MsgTypeError = 0;
	final byte MsgTypeHandshakeServerHello = 4;

	String host;
	int port;
	SocketInitialiser si;
	int delay;

	boolean sslv2Supported = false;

	public static final int SSLv2_UNKNOWN = 0;
	public static final int SSLv2_CLOSESOCKET = 1;
	public static final int SSLv2_NOCIPHER = 2;
	public static final int SSLv2_ERROR = 3;
	public static final int SSLv2_RESET = 4;
	public static final int SSLv2_SUPPORTED = 5;
	public static final int SSLv2_IMPLERROR = 6;

	int sslv2Behavior;

	public static final String[] SSLv2Ciphers = {
		"SSL2_RSA_WITH_RC4_128_MD5",
		"SSL2_RSA_WITH_RC4_128_EXPORT40_MD5",
		"SSL2_RSA_WITH_RC2_128_CBC_MD5",
		"SSL2_RSA_WITH_RC2_128_CBC_EXPORT40_MD5",
		"SSL2_RSA_WITH_IDEA_128_CBC_MD5",
		"SSL2_RSA_WITH_DES_64_CBC_MD5",
		"SSL2_RSA_WITH_DES_192_EDE3_CBC_MD5"
	};
	byte[] sslClientHellov2 = {
		/* 2-byte len spec, 0x2b bytes */
		(byte)0x80, (byte)0x2e,
		/* msg type: client hello */
		(byte)0x01,
		/* version 2 */
		(byte)0x00, (byte)0x02,
		/* cipher spec len */
		(byte)0x00, (byte)0x15,
		/* session id len */
		(byte)0x00, (byte)0x00,
		/* challenge len */
		(byte)0x00, (byte)0x10,
		/* SSL2_RC2_128_EXPORT40_CBC_WITH_MD5 */
		(byte)0x04, (byte)0x00, (byte)0x80, 
		/* SSL2_RC4_128_EXPORT40_WITH_MD5 */
		(byte)0x02, (byte)0x00, (byte)0x80,
		/* SSL2_DES_64_CBC_WITH_MD5 */
		(byte)0x06, (byte)0x00, (byte)0x40, 
		/* SSL2_IDEA_128_CBC_WITH_MD5 */
		(byte)0x05, (byte)0x00, (byte)0x80,
		/* SSL2_RC2_CBC_128_CBC_WITH_MD5 */
		(byte)0x03, (byte)0x00, (byte)0x80, 
		/* SSL2_RC4_128_WITH_MD5 */
		(byte)0x01, (byte)0x00, (byte)0x80, 
		/* SSL2_DES_192_EDE3_CBC_WITH_MD5 */
		(byte)0x07, (byte)0x00, (byte)0xc0,
		/* Challenge byte */
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00
	};

	LinkedHashSet acceptedSSLv2CS;


	public SSLv2ConfigCollector(String theHost, int thePort) {
		this(theHost, thePort, null);
	}


	public SSLv2ConfigCollector(String theHost, int thePort,
			   SocketInitialiser theSI) {
		host = theHost;
		port = thePort;
		delay = 0;
		setSocketInitialiser(theSI);
		acceptedSSLv2CS = new LinkedHashSet();
	}


	public void setSocketInitialiser(SocketInitialiser sockInit) {
		si = sockInit;
	}


	public void setDelay(int parmDelay) {
		delay = parmDelay;
	}


	public Set getAcceptedSSLv2CipherSuites() {
		return (Set)acceptedSSLv2CS;
	}


	public boolean supportsSSLv2() {
		return sslv2Supported;
	}


	public int getSSLv2Behavior() {
		return sslv2Behavior;
	}


	public void collectConfig()
		throws IOException, FingerprintError, FingerprintException {

		checkSslV2();

	}


	private String zeroPad(String s, int len) {
		StringBuffer buf = new StringBuffer();
		for (int i = len-s.length();  i-->0;  ) {
			buf.append("0");
		}
		buf.append(s);
		return new String(buf);
	}


	private void checkResponseSSLv2(InputStream in)
		throws IOException, FingerprintException {

		int n, len, padlen;
		byte[] resp = new byte[32768];
		byte[] hdrbuf = new byte[3];
		byte[] ciphersuitebytes;
		final int fixedLen = 11;
		int hdrlen;
		int sessionIdHit;
		int certType;
		int serverVersion;
		int certLen;
		int cipherSpecLen;
		int connIdLen;

		// Header is at least two bytes long
		for (n = 0;  n < 2;  ) {
			n += in.read(hdrbuf, n, 2-n);
		}

		if ((hdrbuf[0] & 0x80) != 0) {
			/* 2-byte record length format */
			len = (((int)hdrbuf[0] & 0x7f) << 8)
				| ((int)hdrbuf[1] & 0xff);
			padlen = 0;
			hdrlen = 2;
		} else {
			/* 3-byte record length, so read one more byte */
			n = in.read(hdrbuf, 2, 1);
			len = (((int)hdrbuf[0] & 0x3f) << 8)
				| ((int)hdrbuf[1] & 0xff);
			padlen = (int)hdrbuf[2] & 0xff;
			hdrlen = 3;
		}
		
		if (Debug.get(Debug.CheckSSLv2)) {
			System.err.println("checkResponseSSLv2: Record len is "
					   +n+" bytes");
			System.err.print("  >>> ");
			for (int i = 0;  i < hdrlen;  i++) {
				int val = hdrbuf[i] & 0xff;
				System.err.print(
				     zeroPad(Integer.toHexString(val), 2)
				     +" ");
			}
			System.err.println();
		}

		if ( (len < 0)
		     || ( (hdrlen == 2) && (len >= 32768) )
		     || ( (hdrlen == 3) && (len >= 16384) ) ) {
			throw new SSLv2ProtoException(
					  "Invalid SSLv2 record: "
				         +"Invalid record length");
		}

		/* Now read the full record */
		for (n = 0;  n < len;  ) {
			n += in.read(resp, n, len-n);
		}

		if (Debug.get(Debug.CheckSSLv2)) {
			int m = java.lang.Math.min(n, fixedLen);
			System.err.print("  >>> ");
			for (int i = 0;  i < m;  i++) {
				int val = resp[i] & 0xff;
				System.err.print(
				     zeroPad(Integer.toHexString(val), 2)
				     +" ");
			}
			System.err.println();
		}

		int messageType = resp[0];
		if (Debug.get(Debug.CheckSSLv2)) {
			System.err.println("checkResponseSSLv2: messageType "+
					   messageType);
		}
		if (messageType == MsgTypeError) {
			throw new SSLv2HandshakeException(
						  "SSLv2 error message");
		}
		if (messageType != MsgTypeHandshakeServerHello) {
			throw new SSLv2ProtoException(
						 "Non-Handshake message");
		}

		/* Ok, we got a server hello message */
		if (len < fixedLen) {
			throw new SSLv2ProtoException(
					     "Invalid SSLv2 server hello: "
					    +"record too short");
		}

		sessionIdHit = (int)resp[1] & 0xff;
		certType = (int)resp[2] & 0xff;
		serverVersion = (((int)resp[3] & 0xff) << 8)
			| ((int)resp[4] & 0xff);
		certLen = (((int)resp[5] & 0xff) << 8)
			| ((int)resp[6] & 0xff);
		cipherSpecLen = (((int)resp[7] & 0xff) << 8)
			| ((int)resp[8] & 0xff);
		connIdLen = (((int)resp[9] & 0xff) << 8)
			| ((int)resp[10] & 0xff);

		if (Debug.get(Debug.CheckSSLv2)) {
			System.err.println("                    sessionIdHit "
					   +sessionIdHit);
			System.err.println("                    certType "
					   +certType);
			System.err.println("                    serverVersion "
					   +serverVersion);
			System.err.println("                    certLen "
					   +certLen);
			System.err.println("                    cipherSpecLen "
					   +cipherSpecLen + " -> "
					   +cipherSpecLen / 3
					   +" ciphersuites");
			System.err.println("                    connIdLen "
					   +connIdLen);
		}

		if ( (certLen < 0 ) || (cipherSpecLen < 0)
		     || (connIdLen < 0)
		     || (certLen > len) || (cipherSpecLen > len)
		     || (connIdLen > len)
		     || (fixedLen+certLen > len)
		     || (fixedLen+certLen+cipherSpecLen > len)
		     || (fixedLen+certLen+cipherSpecLen+connIdLen > len) ) {
			throw new SSLv2ProtoException(
					      "Invalid SSLv2 server hello: "
					     +"Inconsistent lengths");
		}

		if (serverVersion != 0x0002) {
			throw new SSLv2ProtoException(
						"Wrong SSL version: "
					       +"version 2 expected");
		}

		// prepare to read certificate data
		ByteArrayInputStream rawCertData
			= new ByteArrayInputStream(resp, fixedLen, certLen);
		
		/* Now check that list of cipher specs is non-empty */
		if (cipherSpecLen == 0) {
			throw new SSLv2NoCipherException("No SSLv2 "
						     +"ciphersuites "
						     +"accepted by server");
		}

		byte[] rawCipherSpecData = new byte[cipherSpecLen];
		System.arraycopy(resp, fixedLen+certLen,
				 rawCipherSpecData, 0, cipherSpecLen);

		if ((cipherSpecLen - (cipherSpecLen/3) * 3) != 0) {
			throw new SSLv2ProtoException(
						"Invalid SSLv2 server hello: "
					       +"Invalid cipherspec "
					       +"length");
		}

		for (int i = 0;  i < cipherSpecLen;  i += 3) {
			int idx = rawCipherSpecData[i+0];
			if ( (idx < 1) || (idx > SSLv2Ciphers.length) ) {
				throw new SSLv2ProtoException(
						    "Invalid SSLv2 cipher");
			} else {
				String cipherName = SSLv2Ciphers[idx-1];
				if (Debug.get(Debug.CheckSSLv2)) {
					System.err.println("  Accepted "
							   +cipherName);
				}
				CipherSuiteData d
					= new CipherSuiteData(cipherName,
							      "SSLv2");
				acceptedSSLv2CS.add(d);
			}
		}

		/* Seems that the server goes on with the SSLv2 handshake,
		 * so assume it will go the full length of the protocol
		 */
	}


	public void checkSslV2()
		throws IOException, FingerprintException, FingerprintError {

		byte[] resp = new byte[32];
		Socket s;
		InputStream in;
		OutputStream out;
		int n;

		sslv2Behavior = SSLv2_UNKNOWN;
		sslv2Supported = false;
		try {
			if (si != null) {
				s = si.createSocket(host, port);
			} else {
				s = new Socket(host, port);
			}
		} catch (NoStartTlsException e) {
			sslv2Behavior = SSLv2_UNKNOWN;
			sslv2Supported = false;
			if (Debug.get(Debug.CheckSSLv2)) {
				System.err.println(e.getClass().getName()+": "
						   +e.getMessage());
			}
			NoSSLException se = new
				NoSSLException(LocMsg.pr("e_conn_err",
						       e.getMessage()), e);
			throw(se);
		} catch (SocketTimeoutException e) {
			sslv2Behavior = SSLv2_UNKNOWN;
			sslv2Supported = false;
			if (Debug.get(Debug.CheckSSLv2)) {
				System.err.println(e.getClass().getName()+": "
						   +e.getMessage());
			}
			NoSSLException se = new
				NoSSLException(LocMsg.pr("e_conn_time",
						       e.getMessage()), e);
			throw(se);
		} catch (ConnectException e) {
			sslv2Behavior = SSLv2_UNKNOWN;
			sslv2Supported = false;
			if (Debug.get(Debug.CheckSSLv2)) {
				System.err.println(e.getClass().getName()+": "
						   +e.getMessage());
			}
			NoSSLException se = new
				NoSSLException(LocMsg.pr("e_conn_time",
						       e.getMessage()), e);
			throw(se);
		}

		/* Send SSLv2 client hello with all cipher suites enabled
		 * and check response. If we get a handshake
		 * message, the server seems to understand and
		 * support SSLv2. If it closes the connection,
		 * it does not.
		 */

		// If delay is set, wait the define time before
		// actually sending the request
		if (delay > 0) {
			if (Debug.get(Debug.Delay)) {
				System.err.println("Delaying request.");
			}
			try {
				Thread.sleep(delay);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
		}

		try {
			/* Send prepared SSL2 client hello packet */
			if (Debug.get(Debug.CheckSSLv2)) {
				System.err.println("Sending SSLv2 Client "
						   +"Hello ...");
			}

			out = s.getOutputStream();
			out.write(sslClientHellov2);
			out.flush();
			in = s.getInputStream();
			checkResponseSSLv2(in);
			sslv2Supported = true;
			sslv2Behavior = SSLv2_SUPPORTED;
		} catch (SSLv2HandshakeException e) {
			if (Debug.get(Debug.CheckSSLv2)) {
				System.err.println("SSLv2HandshakeException: "
					       	   +e.getMessage());
			}
			sslv2Supported = false;
			sslv2Behavior = SSLv2_ERROR;
		} catch (SSLv2ProtoException e) {
			if (Debug.get(Debug.CheckSSLv2)) {
				System.err.println("SSLv2ProtoException: "
					       	   +e.getMessage());
			}
			sslv2Supported = false;
			sslv2Behavior = SSLv2_IMPLERROR;
		} catch (SSLv2NoCipherException e) {
			if (Debug.get(Debug.CheckSSLv2)) {
				System.err.println(
						   "SSLv2NoCipherException: "
						   +e.getMessage());
			}
			sslv2Supported = false;
			sslv2Behavior = SSLv2_NOCIPHER;
		} catch (EOFException e) {
			if (Debug.get(Debug.CheckSSLv2)) {
				System.err.println("EOFException: "
						   +e.getMessage());
			}
			sslv2Supported = false;
			sslv2Behavior = SSLv2_CLOSESOCKET;
		} catch (ConnectException e) {
			// Server resets connection
			if (Debug.get(Debug.CheckSSLv2)) {
				System.err.println("ConnectException: "
						   +e.getMessage());
			}
			sslv2Supported = false;
			sslv2Behavior = SSLv2_RESET;
		} catch (SocketException e) {
			// Server resets connection
			if (Debug.get(Debug.CheckSSLv2)) {
				System.err.println("SocketException: "
						   +e.getMessage());
			}
			// FIXME: This is a hack to detect
			// a connection reset. Java seems to
			// throw only a SocketException, but
			// nothing more specific.
			// Thus we have to catch all SocketExceptions
			// and possibly pass them on...
			if (e.getMessage().equals("Connection reset")) {
				sslv2Supported = false;
				sslv2Behavior = SSLv2_RESET;
			} else {
				throw new IOException(e);
			}
		}
		if (si != null) {
			si.decommissionSocket(s);
		}
		s.close();
	}


}
