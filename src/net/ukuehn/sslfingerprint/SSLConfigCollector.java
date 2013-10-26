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

/*
 * The basic idea behind the collection process is that when an SSL
 * handshake completes successfully, we know that the cipher suite
 * selected by the server is one that is supported. If, however, an
 * SSL handshake does not yield a connection we know that _all_
 * cipher suites offered by the client are rejected by the server.
 *
 * Thus, the strategy for fast collection of all supported cipher suites
 * is to start with the full set and iteratively substract the cipher suites
 * of successful handshakes from the set of cipher suites offered by the
 * client, i.e. the SSL Configuration collector. Briefly, this is a
 * substractive approach.
 *
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

import net.ukuehn.security.NullTrustManager;
import net.ukuehn.security.CertValidator;


	
public class SSLConfigCollector {

	final byte MsgTypeError = 0;
	final byte MsgTypeHandshakeServerHello = 4;

	String host;
	int port;
	SocketInitialiser si;
	CertValidator cv;
	int delay;
	boolean initialRequest;

	boolean allowSSLv2Hello = false;
	String[] disabledProtos = { "SSLv2Hello" };

	String[] disabledSuites;
	boolean allowKerb = false;
	boolean allSupported = false;

	LinkedHashSet<String> acceptedProto;
	LinkedHashSet acceptedCS;
	LinkedHashSet rejectedCS;

	Certificate[] certs;
	String certCipherSuiteName;
	boolean certsVerify;
	boolean certNameMatch;


	protected void reset() {
		acceptedProto = new LinkedHashSet<String>();
		acceptedCS = new LinkedHashSet();
		rejectedCS = new LinkedHashSet();
		cv = null;
		certsVerify = false;
		certNameMatch = false;
		initialRequest = true;
	}


	public SSLConfigCollector(String theHost, int thePort) {
		this(theHost, thePort, null);
	}


	public SSLConfigCollector(String theHost, int thePort,
			   SocketInitialiser theSI) {
		host = theHost;
		port = thePort;
		si = null;
		delay = 0;
		setSocketInitialiser(theSI);
		reset();
		disabledSuites = null;
	}


	protected void initDisabledSuites(SSLSocketFactory f) {
		prepareKRBSuites(f);
	}


	protected void prepareKRBSuites(SSLSocketFactory f) {

		if (allowKerb) {
			disabledSuites = new String[0];
			return;
		}
		try {
			SSLSocket tssock = (SSLSocket)f.createSocket();
			String[] supportedSuites
				= tssock.getSupportedCipherSuites();
			tssock.close();

			int nkrb5 = 0;
			for (int i = 0;  i < supportedSuites.length;  i++) {
				if (supportedSuites[i].indexOf("KRB5") >= 0) {
					nkrb5 += 1;
				}
			}

			if (Debug.get(Debug.CollectSuites)) {
				System.err.println("Found "+nkrb5+
						   "ciphersuites with KRB5, "+
						   " disabling them...");
			}
			disabledSuites = new String[nkrb5];
			nkrb5 = 0;
			for (int i = 0;  i < supportedSuites.length;  i++) {
				if (supportedSuites[i].indexOf("KRB5") >= 0) {
					if (Debug.get(Debug.CollectSuites)) {
						System.err.println(
							"Disabling "+
							supportedSuites[i]);
					}
					disabledSuites[nkrb5]
						= supportedSuites[i];
					nkrb5 += 1;
				}
			}
		} catch (IOException e) {
			// ignore here
		}
	}


	protected void disableProtos(LinkedHashSet<String> fullProtoSet) {
		for (int i = 0;  i < disabledProtos.length;  i++) {
			/* Sun's jsse does not support SSLv2, but an
			 * SSLv3 client hello encapsulated in SSLv2
			 * packet. So as a test this is completely
			 * worthless. Skip it.
			 */
			fullProtoSet.remove(disabledProtos[i]);
		}
	}


	protected void disableCiphers(LinkedHashSet<String> fullSuiteSet) {
		for (int i = 0;  i < disabledSuites.length;  i++) {
			fullSuiteSet.remove(disabledSuites[i]);
		}
	}


	public void setSocketInitialiser(SocketInitialiser sockInit) {
		si = sockInit;
	}


	public void setCertValidator(CertValidator certval) {
		cv = certval;
	}


	public void setDelay(int parmDelay) {
		delay = parmDelay;
	}


	public void setAllowSSLv2Hello(boolean allowed) {
		boolean allowSSLv2Hello = allowed;
	}


	public void setAllowKerberos(boolean parmAllow) {
		allowKerb = parmAllow;
		disabledSuites = null;
	}


	public void setAllSupported(boolean parmAllow) {
		allSupported = parmAllow;
	}


	public Set getAcceptedCipherSuites() {
		return (Set)acceptedCS;
	}


	public Set getRejectedCipherSuites() {
		return (Set)rejectedCS;
	}


	public Set<String> getSupportedProtos() {
		return (Set<String>)acceptedProto;
	}


	public Certificate[] getServerCertificates() {
		return certs;
	}


	public boolean serverCertificateVerifies() {
		return certsVerify;
	}


	public boolean serverCertNameMatch() {
		return certNameMatch;
	}


	protected Socket newSocket(String host, int port)
		throws IOException, FingerprintException, FingerprintError {

		Socket s;
		if (si != null) {
			s = si.createSocket(host, port);
		} else {
			s = new Socket(host, port);
		}
		return s;
	}


	protected Socket newSocket()
		throws IOException, FingerprintException, FingerprintError {

		Socket s;
		if (si != null) {
			s = si.createSocket(host, port);
		} else {
			s = new Socket(host, port);
		}
		return s;
	}


	protected void debugSets(LinkedHashSet<String> protos,
				 LinkedHashSet<String> suites) {
		
		String[] currProtos = protos.toArray(new String[1]);
		String[] currSuites = suites.toArray(new String[1]);
		System.err.println("No protocols in set: "+protos.size());
		System.err.println("No protocols in arr: "+currProtos.length);
		for (int i = 0;  i < currProtos.length;  i++) {
			System.err.println("  Protocol "+currProtos[i]);
		}
		for (int i = 0;  i < currSuites.length;  i++) {
			System.err.println("  Suite "+currSuites[i]);
		}
	}


	public void collectConfig()
		throws IOException, FingerprintException, FingerprintError {

		LinkedHashSet<String> fullProtoSet
			= new LinkedHashSet<String>();
		LinkedHashSet<String> fullSuiteSet
			= new LinkedHashSet<String>();

		SSLContext sc = null;
		X509TrustManager[] tm = { new NullTrustManager() };

		/* Get SSL Context, and disable certificate verification
		 * by using an "accept all" trust manager
		 */
		try {
			sc = SSLContext.getInstance("SSL");
			sc.init(null, tm, null);
		} catch (java.security.KeyManagementException e) {
			/* Ignore, should not occur, as key manager is
			 * not provided anyway in the call
			 */
		} catch (NoSuchAlgorithmException e) {
			throw new InstallationError(
				      LocMsg.pr("e_no_java_ssl"), e);
		}

		SSLSocketFactory f =
			(SSLSocketFactory)sc.getSocketFactory();
		if (disabledSuites == null) {
			initDisabledSuites(f);
		}
		SSLSocket tssock = (SSLSocket)f.createSocket();
		String[] protos;
		String[] suites;

		if (allSupported) {
			protos = tssock.getSupportedProtocols();
			suites = tssock.getSupportedCipherSuites();
		} else {
			protos = tssock.getEnabledProtocols();
			suites = tssock.getEnabledCipherSuites();
		}
		tssock.close();
		for (int i = 0;  i < protos.length;  i++) {
			fullProtoSet.add(protos[i]);
		}
		for (int i = 0;  i < suites.length;  i++) {
			fullSuiteSet.add(suites[i]);
		}
		disableProtos(fullProtoSet);
		disableCiphers(fullSuiteSet);

		collectProtocols(f, fullSuiteSet, fullProtoSet);
		collectCipherSuites(f, fullSuiteSet, fullProtoSet);
	}


	private void addRejectedSet(LinkedHashSet<String> suiteSet) {

		for (Iterator<String>
			     it = suiteSet.iterator();
		     it.hasNext();  /* */ ) {
			String cs = (String)it.next();
			CipherSuiteData d =
				new CipherSuiteData(cs);
			rejectedCS.add(d);
			if (Debug.get(Debug.CollectSuites)) {
				System.err.println(
						   "-- adding "
						   +cs+" to rejected "
						   +"cipher suites");
			}
		}
	}


	protected void collectCipherSuites(SSLSocketFactory f,
					   LinkedHashSet<String> suiteSet,
					   LinkedHashSet<String> protoSet)
		throws IOException, FingerprintException, FingerprintError {

		LinkedHashSet<String> currSuiteSet
			= (LinkedHashSet<String>)suiteSet.clone();
		LinkedHashSet<String> currProtoSet
			= (LinkedHashSet<String>)protoSet.clone();
		String[] currProtos;
		String[] currSuites;

		if (Debug.get(Debug.CollectSuites)) {
			System.err.println("Start collecting ciphersuites");
		}
		
		while (currSuiteSet.size() > 0) {

			if (Debug.get(Debug.CollectSuites)) {
				debugSets(currProtoSet, currSuiteSet);
			}

			Socket s = null;
			SSLSocket ssock = null;

			try {
				s = newSocket();
				ssock = (SSLSocket)f.createSocket(s,
				                          host, port, true);
			} catch (ConnectException e) {
				throw new
				      NoSSLException(LocMsg.pr("e_conn_err",
						       e.getMessage()), e);
			} catch (HttpProxyIOException e) {
				throw new IOException(e);
			} catch (NoStartTlsException e) {
				throw new NoSSLException(e);
			} catch (InitialiserException e) {
				throw new NoSSLException(e);
			} catch (FingerprintException e) {
				throw new NoSSLException(e);
			} catch (SocketTimeoutException e) {
				throw new NoSSLException(e);
			}

			currProtos
				= currProtoSet.toArray(new String[1]);
			currSuites
				= currSuiteSet.toArray(new String[1]);
			ssock.setEnabledProtocols(currProtos);
			ssock.setEnabledCipherSuites(currSuites);

			// If a delay is set, wait some time, except for
			// the first request
			if (!initialRequest && (delay > 0)) {
				if (Debug.get(Debug.Delay)) {
					System.err.println(
						    "Delaying request.");
				}
				try {
					Thread.sleep(delay);
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();
				}
			}
			initialRequest = false;

			try {
				ssock.startHandshake();
				SSLSession session = ssock.getSession();
				String cs = session.getCipherSuite();

				CipherSuiteData d = new CipherSuiteData(cs);
				recordServerCertificate(ssock, d);
				acceptedCS.add(d);

				session.invalidate();
				currSuiteSet.remove(cs);

				if (Debug.get(Debug.CollectSuites)) {
					System.err.println("==> Handshake "
							   +"completed with "
							   +cs);
				}
				ssock.close();
			} catch (SSLHandshakeException e) {
				if (Debug.get(Debug.CollectSuites)) {
					System.err.println("==> Handshake "
							   +"failed");
					System.err.println("  "+e.toString());
				}
				addRejectedSet(currSuiteSet);
				currSuiteSet.clear();
				break;
			} catch (ConnectException e) {
				if (Debug.get(Debug.CollectSuites)) {
					System.err.println("==> Handshake "
							   +"failed");
					System.err.println("  "+e.toString());
				}
				addRejectedSet(currSuiteSet);
				currSuiteSet.clear();
				throw new NoSSLException(e);
			} catch (EOFException e) {
				if (Debug.get(Debug.CollectSuites)) {
					System.err.println("==> Handshake "
							   +"failed");
					System.err.println("  "+e.toString());
				}
				addRejectedSet(currSuiteSet);
				currSuiteSet.clear();
				break;
			} catch (SocketException e) {
				if (Debug.get(Debug.CollectSuites)) {
					System.err.println("==> Handshake "
							   +"failed");
					System.err.println("  "+e.toString());
				}
				// FIXME: This is a hack to detect
				// a connection reset. Java seems to
				// throw only a SocketException, but
				// nothing more specific.
				// Thus we have to catch all SocketExceptions
				// and possibly pass them on...
				if (e.getMessage()
				    .equals("Connection reset")) {
					addRejectedSet(currSuiteSet);
					currSuiteSet.clear();
					break;
				} else {
					throw new IOException(e);
				}
			}
		}
	}


	protected void collectProtocols(SSLSocketFactory f,
					LinkedHashSet<String> suiteSet,
					LinkedHashSet<String> protoSet)
		throws IOException, FingerprintException, FingerprintError {

		LinkedHashSet<String> currSuiteSet
			= (LinkedHashSet<String>)suiteSet.clone();
		LinkedHashSet<String> currProtoSet
			= (LinkedHashSet<String>)protoSet.clone();
		String[] currProtos;
		String[] currSuites;

		if (Debug.get(Debug.CollectSuites)) {
			System.err.println("Start collecting protocols");
		}
		
		while (currProtoSet.size() > 0) {

			if (Debug.get(Debug.CollectSuites)) {
				debugSets(currProtoSet, currSuiteSet);
			}

			Socket s = null;
			SSLSocket ssock = null;

			try {
				s = newSocket();
				ssock = (SSLSocket)f.createSocket(s,
				                          host, port, true);
			} catch (ConnectException e) {
				throw new
				      NoSSLException(LocMsg.pr("e_conn_err",
						       e.getMessage()), e);
			} catch (HttpProxyIOException e) {
				throw new IOException(e);
			} catch (NoStartTlsException e) {
				throw new NoSSLException(e);
			} catch (InitialiserException e) {
				throw new NoSSLException(e);
			} catch (FingerprintException e) {
				throw new NoSSLException(e);
			} catch (SocketTimeoutException e) {
				throw new NoSSLException(e);
			}

			currProtos
				= currProtoSet.toArray(new String[0]);
			currSuites
				= currSuiteSet.toArray(new String[0]);
			ssock.setEnabledProtocols(currProtos);
			ssock.setEnabledCipherSuites(currSuites);

			// If a delay is set, wait some time, except for
			// the first request
			if (!initialRequest && (delay > 0)) {
				if (Debug.get(Debug.Delay)) {
					System.err.println(
						    "Delaying request.");
				}
				try {
					Thread.sleep(delay);
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();
				}
			}
			initialRequest = false;

			try {
				ssock.startHandshake();
				SSLSession session = ssock.getSession();
				String proto = session.getProtocol();

				//String cs = session.getCipherSuite();
				//CipherSuiteData d = new CipherSuiteData(cs);
				//recordServerCertificate(ssock, d);

				acceptedProto.add(proto);

				session.invalidate();
				currProtoSet.remove(proto);

				if (Debug.get(Debug.CollectSuites)) {
					System.err.println("==> Handshake "
							   +"completed using "
							   +proto);
				}
				ssock.close();
			} catch (SSLHandshakeException e) {
				if (Debug.get(Debug.CollectSuites)) {
					System.err.println("==> Handshake "
							   +"failed");
					System.err.println("  "+e.toString());
				}
				currProtoSet.clear();
				break;
			} catch (ConnectException e) {
				if (Debug.get(Debug.CollectSuites)) {
					System.err.println("==> Handshake "
							   +"failed");
					System.err.println("  "+e.toString());
				}
				currProtoSet.clear();
				throw new NoSSLException(e);
			} catch (EOFException e) {
				if (Debug.get(Debug.CollectSuites)) {
					System.err.println("==> Handshake "
							   +"failed");
					System.err.println("  "+e.toString());
				}
				currProtoSet.clear();
				break;
			} catch (SocketException e) {
				if (Debug.get(Debug.CollectSuites)) {
					System.err.println("==> Handshake "
							   +"failed");
					System.err.println("  "+e.toString());
				}
				// FIXME: This is a hack to detect
				// a connection reset. Java seems to
				// throw only a SocketException, but
				// nothing more specific.
				// Thus we have to catch all SocketExceptions
				// and possibly pass them on...
				if (e.getMessage()
				    .equals("Connection reset")) {
					currProtoSet.clear();
					break;
				} else {
					throw new IOException(e);
				}
			}
		}
	}


	protected void recordServerCertificate(SSLSocket ssock,
					       CipherSuiteData cs)
		throws IOException {

		if (Debug.get(Debug.Certs)) {
			System.err.println("SSLConfigCollector."
					   +"recordServerCertificate(..., "
					   +cs.name+")");
		}

		if (certs != null) {
			/* If we already have the certificate chain,
			 * leave it at that.
			 * FIXME: in a future version, check if server
			 * returns always the same certificate chain.
			 */
			if (Debug.get(Debug.Certs)) {
				System.err.println(
					 "SSLConfigCollector."
					 +"recordServerCertificate: already "
					 +"have one.");
			}
			return;
		}

		/* Get the certificate chain */
		SSLSession session = ssock.getSession();
		try {
			certs = session.getPeerCertificates();
			certCipherSuiteName = cs.name;
			
			if (cv != null) {
				if (Debug.get(Debug.Certs)) {
					System.err.println(
						"Verifying certs using "
						+"auth type "
						+cs.kex);
				}
				certsVerify = cv.isValidChain(certs,
							      cs.kex);
				certNameMatch = cv.nameMatches(certs[0], host);
				if (Debug.get(Debug.Certs)) {
					String res;
					res = (certsVerify)?"OK":"failed";
					System.err.println(
						"Cert verification "+res);
					System.err.println(
					   "Cert name matches: "
					   +String.valueOf(certNameMatch)
					   );
				}
			} else {
				if (Debug.get(Debug.Certs)) {
					System.err.println(
						"SSLConfigCollector."
						+"recordServerCertificate: "
						+"no verifier set.");
				}
			}
			
		} catch (SSLPeerUnverifiedException e) {
			/* do nothing here */
		}
		session.invalidate();
	}


	protected void setSSLv2Hello(SSLSocket ssock, boolean allow) {
		if (allow) {
			/* We are done, as Java for now does
			 * support SSLv2Hello pseudo protocol
			 */
			return;
		}
		String[] pr = ssock.getEnabledProtocols();
		int i, n; 
		for (i = 0, n = 0;  i < pr.length;  i++) {
			if (pr[i] != "SSLv2Hello") {
				n += 1;
			}
		}
		String[] newPr = new String[n];
		for (i = 0, n = 0;  i < pr.length;  i++) {
			if (pr[i] != "SSLv2Hello") {
				newPr[n++] = pr[i];
			}
		}
		try {
			ssock.setEnabledProtocols(newPr);
		} catch (Exception e) {
			/* ignore, should not occur */
		}
	}


	public void probe()
		throws IOException, FingerprintError, FingerprintException {

		SSLContext sc = null;
		X509TrustManager[] tm = { new NullTrustManager() };
		LinkedHashSet<String> protoSet
			= new LinkedHashSet<String>();
		LinkedHashSet<String> suiteSet
			= new LinkedHashSet<String>();

		/* Get SSL Context, and disable certificate verification
		 * by using an "accept all" trust manager
		 */
		try {
			sc = SSLContext.getInstance("SSL");
			sc.init(null, tm, null);
		} catch (java.security.KeyManagementException e) {
			/* Ignore, should not occur, as key manager is
			 * not provided anyway in the call, but
			 * otherwise there seems to be a serious
			 * problem with the installation.
			 */
			throw new InstallationError(e);
		} catch (NoSuchAlgorithmException e) {
			throw new InstallationError(
				      LocMsg.pr("e_no_java_ssl"), e);
		}

		SSLSocketFactory f = (SSLSocketFactory)sc.getSocketFactory();

		Socket s;
		SSLSocket ssock;

		try {
			if (si != null) {
				s = si.createSocket(host, port);
			} else {
				s = new Socket(host, port);
			}
			ssock = (SSLSocket)f.createSocket(s, host, port, true);
		} catch (ConnectException e) {
			throw new
				NoSSLException(LocMsg.pr("e_conn_err",
							 e.getMessage()), e);
		} catch (HttpProxyIOException e) {
			throw new IOException(e);
		} catch (NoStartTlsException e) {
			throw new NoSSLException(e);
		} catch (InitialiserException e) {
			throw new NoSSLException(e);
		} catch (FingerprintException e) {
			throw new NoSSLException(e);
		} catch (SocketTimeoutException e) {
			throw new NoSSLException(e);
		}

		// If a delay is set, wait some time, except for
		// the first request
		if (!initialRequest && (delay > 0)) {
			if (Debug.get(Debug.Delay)) {
				System.err.println("Delaying request.");
			}
			try {
				Thread.sleep(delay);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
		}
		initialRequest = false;

		try {
			ssock.startHandshake();
			SSLSession session = ssock.getSession();

			String cs = session.getCipherSuite();
			CipherSuiteData d = new CipherSuiteData(cs);
			recordServerCertificate(ssock, d);
			// certs = session.getPeerCertificates();
			if (Debug.get(Debug.CollectSuites)) {
				System.err.println("Handshake with "
						   +host+":"
						   +String.valueOf(port)
						   +" using "+d.name);
			}

			acceptedCS.add(d);

			String proto = session.getProtocol();
			acceptedProto.add(proto);

		} catch (SSLPeerUnverifiedException e) {
			/* Intentionally ignore this one here! */
		} catch (SSLHandshakeException e) {
			if (Debug.get(Debug.CollectSuites)) {
				System.err.println("==> Handshake "
						   +"failed");
				System.err.println("  "+e.toString());
			}
			throw new NoSSLException(e);
		} catch (ConnectException e) {
			if (Debug.get(Debug.CollectSuites)) {
				System.err.println("==> Handshake "
						   +"failed");
				System.err.println("  "+e.toString());
			}
			throw new NoSSLException(e);
		} catch (EOFException e) {
			if (Debug.get(Debug.CollectSuites)) {
				System.err.println("==> Handshake "
						   +"failed");
				System.err.println("  "+e.toString());
			}
			throw new NoSSLException(e);
		} 
		ssock.close();
	}

}
