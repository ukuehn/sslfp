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
import java.util.Iterator;
import java.text.SimpleDateFormat;

import org.xml.sax.SAXException;

import net.ukuehn.xml.*;



public class XMLProbePublisher extends Publisher {

	SimpleXMLWriter xw;
	int verbLevel;


	public XMLProbePublisher(SimpleXMLWriter xmlWr,
				 int verbosityLevel) {
		xw = xmlWr;
		verbLevel = verbosityLevel;
	}


	public void publishHeader() throws IOException, FingerprintError {
		try {
			xw.startDocument();
			xw.startElement("ProbeResults");
		} catch (SAXException e) {
			throw new FingerprintError(e);
		}
	}


	public void publishFooter() throws IOException, FingerprintError {
		try {
			xw.endElement(); // </ProbeResults>
			xw.endDocumentNL();
			xw.flush();
		} catch (SAXException e) {
			throw new FingerprintError(e);
		}
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

		SimpleDateFormat format
			= new SimpleDateFormat(LocMsg.pr("s_dateformat"));
		String resSupport = "unknown";

		switch (pr.sslSupport) {
		case SSLResult.UNSUPPORTED:
			resSupport = "false";
			break;
		case SSLResult.SUPPORTED:
			resSupport = "true";
			break;
		case SSLResult.UNKNOWN:
		default:
			resSupport = "unknown";
			break;
		}

		try {
			xw.startElement("Host");  // <host>
			xw.attribute("Name", pr.host);
			xw.attribute("Port", String.valueOf(pr.port));
			xw.attribute("SSL", resSupport);
			xw.attribute("Date", format.format(pr.startDate));
			if (pr.sslSupport == SSLResult.SUPPORTED) {
				xw.startElement("SSLConfig");
				certificateEssentialsToXML(pr);
				xw.endElement();  // </SSLConfig>
			}

			xw.endElement();  // </host>
		} catch (SAXException e) {
			throw new FingerprintError(e);
		}
	}



	protected void certificateEssentialsToXML(ProbeResult pr)
		throws IOException, FingerprintError, SAXException {
		boolean certNameMatch = false;

		if (pr.certs == null) {
			// no cert, no entry...
			return;
		}
		if (!(pr.certs[0] instanceof X509Certificate)) {
			// no X509 cert, no entry...
			return;
		}

		X509Certificate cert = (X509Certificate)pr.certs[0];
		if (cv != null) {
			certNameMatch = cv.nameMatches(cert, pr.host);
		} else {
			throw new FingerprintError("No certificate validator");
		}

		xw.startElement("Certificate");
		xw.attribute("CertValid",
			     String.valueOf(pr.certVerifies));
		xw.attribute("CertNameMatch",
			     String.valueOf(certNameMatch));
		if (verbLevel > 0) {
			certificateDetailsToXML(cert);
		}
		xw.endElement();  // Certificate
	}


	protected void certificateDetailsToXML(X509Certificate cert)
		throws IOException, FingerprintError, SAXException {

		String subjDN =	cert.getSubjectX500Principal().getName();
		String issuerDN = cert.getIssuerX500Principal().getName();
		boolean selfSigned = subjDN.equals(issuerDN);
		PublicKey pk = cert.getPublicKey();
		String alg = pk.getAlgorithm();

		xw.startElement("CertDetails");
		xw.attribute("CertAlgorithm", alg);

		if (pk instanceof RSAPublicKey) {
			RSAPublicKey rpk = (RSAPublicKey)pk;
			int size = rpk.getModulus().bitLength();

			xw.attribute("KeyLength", String.valueOf(size));
			String hashVal = getRSAKeyHash(rpk);
			if (opensslModHash) {
				xw.attribute("ModHash", hashVal);
			} else {
				xw.attribute("KeyHash", hashVal);
			}
		} else if (pk instanceof DHPublicKey) {
			DHPublicKey dpk = (DHPublicKey)pk;
			int gsize = dpk.getParams().getP().bitLength();
			xw.attribute("KeyLength", String.valueOf(gsize));
		} else if (pk instanceof ECPublicKey) {
			// 
		}
		xw.attribute("SelfSigned", String.valueOf(selfSigned));
		if (verbLevel > 1) {
			xw.attribute("Subject", subjDN);
			xw.attribute("Issuer", issuerDN);
			xw.attribute("ValidFrom",
				     cert.getNotBefore().toString());
			xw.attribute("ValidUntil",
				     cert.getNotAfter().toString());
		}
		xw.endElement(); // </CertDetails>
	}



}
