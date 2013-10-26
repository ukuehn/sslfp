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
import java.security.KeyStore;
import java.security.MessageDigest;

import java.security.NoSuchAlgorithmException;
import java.security.KeyStoreException;

import java.util.Date;
import java.util.Set;
import java.util.LinkedHashSet;
import java.util.Iterator;
import java.text.SimpleDateFormat;

import org.xml.sax.SAXException;

import net.ukuehn.xml.*;



public class XMLFingerprintPublisher extends ClassifyingPublisher {

	SimpleXMLWriter xw;
	int verbLevel;


	public XMLFingerprintPublisher(SimpleXMLWriter xmlWr, Classifier cl,
				       int verbosityLevel) {
		xw = xmlWr;
		verbLevel = verbosityLevel;
		cls = cl;
	}


	public void publishHeader() throws IOException, FingerprintError {
		try {
			xw.startDocument();
			xw.startElement("Analysis");
			//if (verbLevel > 2) {
			//	if (si != null) {
			//		xw.attribute("Initialiser",
			//			     si.getName());
			//	} else {
			//		xw.attribute("Initialiser", "None");
			//	}
			//}
		} catch (SAXException e) {
			throw new FingerprintError(e);
		}
	}


	public void publishFooter() throws IOException, FingerprintError {
		try {
			xw.endElement(); // </analysis>
			xw.endDocumentNL();
		} catch (SAXException e) {
			throw new FingerprintError(e);
		}
	}


	public void publish(SSLResult sr)
		throws IOException, FingerprintError {
		if (sr instanceof FingerprintResult) {
			publish((FingerprintResult)sr);
		} else {
			throw new FingerprintError(
				     "Trying to publish mismatching type"
				     );
		}
	}


	public void publish(FingerprintResult fr)
		throws IOException, FingerprintError {

		SimpleDateFormat format
			= new SimpleDateFormat(LocMsg.pr("s_dateformat"));
		String resSupport = "unknown";

		switch (fr.sslSupport) {
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

		// first, classify results regarding security
		classify(fr);
		try {
			xw.startElement("Host");  // <host>
			xw.attribute("Name", fr.host);
			xw.attribute("Port", String.valueOf(fr.port));
			xw.attribute("SSL", resSupport);
			xw.attribute("Date", format.format(fr.startDate));
			if (fr.sslSupport == SSLResult.SUPPORTED) {
				xw.startElement("SSLConfig");
				protoToXML(fr);
				ciphersuitesToXML(fr);
				certificateToXML(fr);
				xw.endElement();  // </SSLConfig>
			}

			xw.endElement();  // </host>
		} catch (SAXException e) {
			throw new FingerprintError(e);
		}
	}


	protected void protoToXML(FingerprintResult fr)
		throws IOException, FingerprintError, SAXException {
		boolean secureProto = false;
		if (fr.supportsSSLv2) {
			secureProto = (fr.protos.size() > 1);
		} else {
			secureProto = (fr.protos.size() > 0);
		}
		xw.startElement("ProtocolConfig");
		xw.attribute("SecureProto",
			     String.valueOf(secureProto));
		xw.attribute("InsecureProto",
			     String.valueOf(fr.supportsSSLv2));
		if (verbLevel > 1) {
			for (Iterator<String> it = fr.protos.iterator();
			     it.hasNext();  /* in loop */ ) {
				String proto = it.next();
				xw.startElement("ProtoDetail");
				xw.attribute("ProtoName", proto);
				if (verbLevel > 2) {
					String sec;
					sec = (proto.equals("SSL2"))?
						"insecure":"secure";
					xw.attribute("ProtoSupport",
						     String.valueOf(true));
					xw.attribute("ProtoSecurity", sec);
				}
				xw.endElement();
			}
		}
		xw.endElement();
	}


	protected void ciphersuitesToXML(FingerprintResult fr)
		throws IOException, FingerprintError, SAXException {
		xw.startElement("CipherConfig");
		xw.attribute("SecureCiphers",
			     String.valueOf(secCS.size() > 0));
		xw.attribute("ProblematicCiphers",
			     String.valueOf(probCS.size() > 0));
		xw.attribute("InsecureCiphers",
			     String.valueOf(insecCS.size() > 0));
		if (verbLevel > 1) {
			for (Iterator<CipherSuiteData> it = secCS.iterator();
			     it.hasNext();  /* in loop */ ) {
				CipherSuiteData d = it.next();
				xw.startElement("CipherDetail");
				xw.attribute("CipherName", d.name);
				if (verbLevel > 2) {
					xw.attribute("CipherSecurity",
						     "secure");
				}
				if (verbLevel > 3) {
					xw.attribute("CipherSupport",
						     String.valueOf(true));
				}
				xw.endElement();
			}
			for (Iterator<CipherSuiteData> it
				     = probCS.iterator();
			     it.hasNext();  /* in loop */ ) {
				CipherSuiteData d = it.next();
				xw.startElement("CipherDetail");
				xw.attribute("CipherName", d.name);
				if (verbLevel > 2) {
					xw.attribute("CipherSecurity",
						     "problematic");
				}
				if (verbLevel > 3) {
					xw.attribute("CipherSupport",
						     String.valueOf(true));
				}
				xw.endElement();
			}
			for (Iterator<CipherSuiteData> it
				     = insecCS.iterator();
			     it.hasNext();  /* in loop */ ) {
				CipherSuiteData d = it.next();
				xw.startElement("CipherDetail");
				xw.attribute("CipherName", d.name);
				if (verbLevel > 2) {
					xw.attribute("CipherSecurity",
						     "insecure");
				}
				if (verbLevel > 3) {
					xw.attribute("CipherSupport",
						     String.valueOf(true));
				}
				xw.endElement();
			}
			for (Iterator<CipherSuiteData> it
				     = unknownCS.iterator();
			     it.hasNext();  /* in loop */ ) {
				CipherSuiteData d = it.next();
				xw.startElement("CipherDetail");
				xw.attribute("CipherName", d.name);
				if (verbLevel > 2) {
					xw.attribute("CipherSecurity",
						     "unknown");
				}
				if (verbLevel > 3) {
					xw.attribute("CipherSupport",
						     String.valueOf(true));
				}
				xw.endElement();
			}
		}
		xw.endElement(); // </CiphersuiteConfig>
	}


	protected void certificateToXML(FingerprintResult fr)
		throws IOException, FingerprintError, SAXException {

		boolean certNameMatch = false;

		if (fr.certs == null) {
			// no cert, no entry...
			return;
		}
		if (!(fr.certs[0] instanceof X509Certificate)) {
			// no X509 cert, no entry...
			return;
		}
		X509Certificate cert = (X509Certificate)fr.certs[0];

		xw.startElement("Certificate");
		xw.attribute("CertValid",
			     String.valueOf(fr.certVerifies));
		xw.attribute("CertNameMatch",
			     String.valueOf(fr.certNameMatch));
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
			xw.attribute("Issuer", subjDN);
			xw.attribute("ValidFrom",
				     cert.getNotBefore().toString());
			xw.attribute("ValidUntil",
				     cert.getNotAfter().toString());
		}
		xw.endElement(); // </CertDetails>
	}

}
