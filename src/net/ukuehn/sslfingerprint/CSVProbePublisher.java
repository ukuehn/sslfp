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
import java.security.PublicKey;

import java.util.Date;
import java.text.SimpleDateFormat;



public class CSVProbePublisher extends Publisher {

	Log log;
	int verbLevel;


	public CSVProbePublisher(Log logger, int verbosityLevel) {
		log = logger;
		verbLevel = verbosityLevel;
	}


	public void publishHeader() throws IOException, FingerprintError {
		if (verbLevel > 0) {
			log.log(Log.ESSENTIAL,
				LocMsg.pr("s_prompt_check_verb"));
		} else {
			log.log(Log.ESSENTIAL,
				LocMsg.pr("s_prompt_check"));
		}
	}


	public void publishFooter() throws IOException, FingerprintError {
		// nothing
	}


	public void publish(SSLResult sr)
		throws IOException, FingerprintError {
		if (sr instanceof ProbeResult) {
			publish((ProbeResult)sr);
		} else {
			throw new FingerprintError(
				     "Trying to publish mismatching type"
				     );
		}
	}


	public void publish(ProbeResult pr)
		throws IOException, FingerprintError {

		String resSupport;
		SimpleDateFormat format
			= new SimpleDateFormat(LocMsg.pr("s_dateformat"));

		switch (pr.sslSupport) {
		case SSLResult.UNSUPPORTED:
			resSupport = LocMsg.pr("r_checkres_nosupport");
			break;
		case SSLResult.SUPPORTED:
			resSupport = LocMsg.pr("r_checkres_support");
			break;
		case SSLResult.UNKNOWN:
		default:
			resSupport = LocMsg.pr("r_checkres_unknown");
			break;
		}

		if (verbLevel > 0) {
			boolean nameMatch = false;
			String keyhash = new String();
			X509Certificate xcert = null;
			RSAPublicKey rpk = null;
			String certAlg = new String();
			String sLength = new String();
			String sNameMatch = new String();
			String sCertVerifies = new String();
			if (pr.certs != null) {
				if (pr.certs[0] instanceof X509Certificate) {
					xcert = (X509Certificate)pr.certs[0];
				}
				sNameMatch = String.valueOf(nameMatch);
				sCertVerifies
					= String.valueOf(pr.certVerifies);
			}
			if (xcert != null) {
				nameMatch = cv.nameMatches(xcert, pr.host);
				sNameMatch = String.valueOf(nameMatch);
				PublicKey pk = xcert.getPublicKey();
				certAlg = pk.getAlgorithm();
				if (pk instanceof RSAPublicKey) {
					rpk = (RSAPublicKey)pk;
					int n = rpk.getModulus().bitLength();
					sLength = String.valueOf(n);
					keyhash = getRSAKeyHash(rpk);
				} else if (pk instanceof DHPublicKey) {
					DHPublicKey dpk = (DHPublicKey)pk;
					sLength = String.valueOf(
					     dpk.getParams().getP().bitLength()
					     );
				}
			}
			log.log(Log.ESSENTIAL,
				LocMsg.pr("r_probe_summary_verb",
					  pr.host, String.valueOf(pr.port),
					  resSupport,
					  format.format(pr.startDate),
					  sCertVerifies,
					  sNameMatch,
					  certAlg, sLength,
					  keyhash
					  )
				);
		} else {
			log.log(Log.ESSENTIAL,
				LocMsg.pr("r_probe_summary",
					  pr.host, String.valueOf(pr.port),
					  resSupport,
					  format.format(pr.startDate)
					  )
				);
		}
	}



}
