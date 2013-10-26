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


import javax.net.ssl.*;
import javax.security.auth.*;
import javax.net.*;
import javax.crypto.interfaces.*;
import java.net.*;
import java.io.*;

import java.security.cert.*;
import java.security.interfaces.*;

import java.util.Date;

import net.ukuehn.security.CertValidator;



public class SSLProbe extends SSLFingerprint {


	public SSLProbe(String theHost, int thePort) {
		super(theHost, thePort);
	}


	public SSLProbe(String theHost) {
		this(theHost, defaultSSLPort);
	}


	public SSLProbe() {
		this(null, 0);
	}


	public SSLResult fingerprint()
		throws IOException, FingerprintError {

		SSLConfigCollector scc;

		scc = new SSLConfigCollector(host, port, si);
		scc.setCertValidator(cv);

		startDate = new Date();

		sslSupport = SSLResult.UNKNOWN;

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

		try {
			scc.probe();
			sslSupport = SSLResult.SUPPORTED;
			sslSupportReason = null;
		} catch (NoSSLException e) {
			// This exception is thrown when the protocol support
			// for ssl is not available
			sslSupport = SSLResult.UNSUPPORTED;
			sslSupportReason = e.toString();
		} catch (FingerprintException e) {
			sslSupport = SSLResult.UNSUPPORTED;
			sslSupportReason = e.toString();
		} catch (IOException e) {
			sslSupport = SSLResult.UNKNOWN;
			sslSupportReason = e.toString();
		}
		endDate = new Date();

		protos = scc.getSupportedProtos();

		ProbeResult pres
			= new ProbeResult(
				host, port,
				startDate, endDate,
				sslSupport,
				sslSupportReason,
				scc.getServerCertificates(),
				scc.serverCertificateVerifies(),
				scc.serverCertNameMatch());

		pres.setProtosResult(protos);
		return pres;
	}

}
