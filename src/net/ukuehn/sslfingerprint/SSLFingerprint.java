/* -*- java -*-
 *
 * This is sslfingerprint, an fingerprinting and security analysis tool
 * for server ssl configurations.
 *
 * (C) 2010-2013 Ulrich Kuehn <ukuehn@acm.org>
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
import javax.security.auth.*;
import javax.net.*;
import javax.crypto.interfaces.*;
import java.net.*;
import java.io.*;

import java.security.cert.*;
import java.security.interfaces.*;
import java.security.PublicKey;

import java.util.Date;
import java.util.Set;

import net.ukuehn.security.CertValidator;



public class SSLFingerprint {

	static final int defaultSSLPort = 443;

	int sslSupport;
	String sslSupportReason;

	int verbLevel;
	boolean opensslModHash = false;
	int delay;
	boolean initial;
	boolean allowKerb = false;
	boolean allSupported = false;

	String host;
	int port;
	SocketInitialiser si;
	CertValidator cv;

	Date startDate;
	Date endDate;

	Set<String> protos;



	public SSLFingerprint(String theHost, int thePort) {
		verbLevel = 0;
		cv = null;
		delay = 0;
		initial = true;
		setTarget(theHost, thePort);
	}


	public SSLFingerprint(String theHost) {
		this(theHost, defaultSSLPort);
	}


	public SSLFingerprint() {
		this(null, 0);
	}


	public void setTarget(String theHost, int thePort) {
		host = theHost;
		port = thePort;
		protos = null;
	}


	public void setTarget(String theHost) {
		setTarget(theHost, defaultSSLPort);
	}


	public void setModHash(boolean useModHash) {
		opensslModHash = useModHash;
	}


	public void setAllSupported(boolean parmAll) {
		allSupported = parmAll;
	}


	public void setAllowKerberos(boolean parmAllow) {
		allowKerb = parmAllow;
	}


	public void setVerbose(boolean verbose) {
		if (verbose) {
			verbLevel = 1;
		} else {
			verbLevel = 0;
		}
	}


	public void setVerboseLevel(int level) {
		if (level > 0) {
			verbLevel = level;
		} else {
			verbLevel = 0;
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


	/* Run the analysis and run the output method on the
	 * results. Subclasses should override the output methods in
	 * order to obtain the desired output format.
	 */
	public SSLResult fingerprint()
		throws IOException, FingerprintError {

		int res;
		SSLConfigCollector scc;
		SSLv2ConfigCollector scc2;

		startDate = new Date();

		// If a delay is set, wait some time, except for
		// the first request
		if (!initial && (delay > 0)) {
			if (Debug.get(Debug.Delay)) {
				System.err.println("Delaying request.");
			}
			try {
				Thread.sleep(delay);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
		}
		initial = false;

		scc = new SSLConfigCollector(host, port, si);
		scc.setCertValidator(cv);
		scc.setDelay(delay);
		scc.setAllSupported(allSupported);
		scc.setAllowKerberos(allowKerb);
		scc2 = new SSLv2ConfigCollector(host, port, si);
		scc2.setDelay(delay);

		sslSupport = SSLResult.UNKNOWN;
		try {
			scc.collectConfig();
			scc2.collectConfig();
			sslSupport = SSLResult.SUPPORTED;
			sslSupportReason = null;
		} catch (NoSSLException e) {
			// This exception is thrown when the protocol support
			// for ssl is not available
			sslSupport = SSLResult.UNSUPPORTED;
			sslSupportReason = e.toString();
		} catch (FingerprintException e) {
			// Ok, some other problem. So print it out
			// and stop analysis for this host
			//System.err.println(e.toString());
			sslSupport = SSLResult.UNSUPPORTED;
			sslSupportReason = e.toString();
			//outputException(e.toString());
		} catch (IOException e) {
			// Some IO problem, so
			sslSupport = SSLResult.UNKNOWN;
			sslSupportReason = e.toString();

			//e.printStackTrace();

			//outputException(e.toString());
		}
		endDate = new Date();

		protos = scc.getSupportedProtos();
		if (scc2.supportsSSLv2()) {
			protos.add("SSL2");
		}

		FingerprintResult fpres
			= new FingerprintResult(
				   host, port,
				   startDate, endDate,
				   sslSupport,
				   sslSupportReason,
				   scc.getServerCertificates(),
				   scc.serverCertificateVerifies(),
				   scc.serverCertNameMatch());
		fpres.setProtosResult(protos,
				      scc2.supportsSSLv2(),
				      scc2.getSSLv2Behavior());
		fpres.setCiphersuiteResult(scc.getAcceptedCipherSuites(),
				 scc2.getAcceptedSSLv2CipherSuites());
		
		return fpres;
	}


}
