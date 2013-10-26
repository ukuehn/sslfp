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
import java.util.Collection;
import java.util.Iterator;
import java.text.SimpleDateFormat;



public class PlainFingerprintPublisher extends ClassifyingPublisher {

	Log log;
	int verbLevel;
	boolean first;
	String sockIniName;

	public PlainFingerprintPublisher(Log logger,
					 Classifier cl,
					 int verbosityLevel,
					 String siName) {
		log = logger;
		verbLevel = verbosityLevel;
		sockIniName = siName;
		cls = cl;
	}


	public void publishHeader() throws IOException, FingerprintError {
		if (sockIniName != null) {
			log.log(Log.ESSENTIAL,
				LocMsg.pr("s_init", sockIniName));
		}
		first = true;
	}


	public void publishFooter() throws IOException, FingerprintError {
		// nothing
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
		if (log == null) {
			return;
		}
		if (first) {
			log.log(Log.ESSENTIAL,
				LocMsg.pr("s_running_first",
					  fr.host, String.valueOf(fr.port),
					  format.format(fr.startDate))
			);
			first = false;
		} else {
			log.log(Log.ESSENTIAL,
				LocMsg.pr("s_running_cont",
					  fr.host, String.valueOf(fr.port),
					  format.format(fr.startDate))
			);
		}

		log.log(Log.ESSENTIAL,
			LocMsg.pr("s_collection_done",
				  format.format(fr.endDate))
			);
		/*
		 * Ok, here we have all results, so start
		 * with output
		 */
		if (fr.sslSupport == SSLResult.SUPPORTED) {

			// first, classify the results regarding securiy
			classify(fr);

			publishProtoSummary(fr);
			publishProtoDetails(fr);
			publishCSSummary(fr);
			publishCSDetails(fr);

			if (fr.certs != null) {
				publishCertificates(fr);
			}
		} else if (fr.sslSupport == SSLResult.UNSUPPORTED) {
			log.log(LocMsg.pr("r_no_ssl",
					  fr.host, String.valueOf(fr.port)));
		} else if (fr.sslSupport == SSLResult.UNKNOWN) {
			log.log(LocMsg.pr("r_unknown_support",
					  fr.host, String.valueOf(fr.port),
					  fr.reasonNoSupport));
		}
	}


	protected void publishProtoSummary(FingerprintResult fr) {
		if (fr.supportsSSLv2) {
			log.log(Log.ESSENTIAL, LocMsg.pr("r_handshake_insec"));
		} else {
			log.log(Log.ESSENTIAL, LocMsg.pr("r_handshake_sec"));
		}
	}


	protected void publishProtoDetails(FingerprintResult fr) {
		log.log(Log.VERBOSE,
			LocMsg.pr("r_proto_details"));
		CipherSuiteData suites[]
			= fr.ciphersuites.toArray(new CipherSuiteData[0]);
		for (Iterator<String> itr = fr.protos.iterator();
		     itr.hasNext();  /* nothing */ ) {
			String proto = itr.next();
			int sec = cls.classifyProto(proto, suites);
			String secStr = null;
			if (sec == Classification.STRENGTH_SECURE) {
				secStr = LocMsg.pr("r_secure");
			} else if (sec == Classification.STRENGTH_INSECURE) {
				secStr = LocMsg.pr("r_insecure");
			} else {
				secStr = LocMsg.pr("r_unknown");
			}
			log.log(Log.VERBOSE,
				LocMsg.pr("r_proto_conf",
					  proto, secStr));
		}
		if (!fr.supportsSSLv2) {
			String s = LocMsg.pr("r_ssl2_unknown");
			if (fr.sslv2Behavior
			    == SSLv2ConfigCollector.SSLv2_CLOSESOCKET) {
				s = LocMsg.pr("r_ssl2_close");
			} else if (fr.sslv2Behavior
				   == SSLv2ConfigCollector.SSLv2_NOCIPHER) {
				s = LocMsg.pr("r_ssl2_nocipher");
			} else if (fr.sslv2Behavior
				   == SSLv2ConfigCollector.SSLv2_ERROR) {
				s = LocMsg.pr("r_ssl2_error");
			} else if (fr.sslv2Behavior
				   == SSLv2ConfigCollector.SSLv2_RESET) {
				s = LocMsg.pr("r_ssl2_reset");
			} else if (fr.sslv2Behavior
				   == SSLv2ConfigCollector.SSLv2_IMPLERROR) {
				s = LocMsg.pr("r_ssl2_implerror");
			}
			log.log(Log.VERBOSE,
				LocMsg.pr("r_ssl2_behavior", s));
		}
	}


	protected void publishCSSummary(FingerprintResult fr) {
		if ( (secCS.size() == 0) &&
		     (probCS.size() == 0) &&
		     (insecCS.size() == 0) &&
		     (unknownCS.size() == 0) ) {
			log.log(LocMsg.pr("r_no_cs",
					  fr.host,
					  String.valueOf(fr.port)));
			return;
		}
		if (secCS.size() > 0) {
			if ( (insecCS.size() == 0)
			     && (probCS.size() == 0)
			     && (unknownCS.size() == 0) ) {
				log.log(LocMsg.pr("r_cs_ok"));
			} else if (insecCS.size() > 0) {
				log.log(LocMsg.pr("r_cs_insec"));
			} else if (probCS.size() > 0) {
				log.log(LocMsg.pr("r_cs_prob"));
			}
		} else {
			if (probCS.size() > 0) {
				log.log(LocMsg.pr("r_cs_prob"));
			} else {
				log.log(LocMsg.pr("r_cs_nosec"));
			}
		}
		if (unknownCS.size() > 0) {
			log.log(LocMsg.pr("r_hint"));
		}
	}


	protected void publishCSDetails(FingerprintResult fr) {
		if (fr.supportsSSLv2) {
			if (fr.sslv2CS.size() > 0) {
				log.log(Log.VERBOSE,
					LocMsg.pr("r_ssl2_cs_conf"));
			}
			for (Iterator itr = fr.sslv2CS.iterator();
			     itr.hasNext(); /* nothing */ ) {
				CipherSuiteData d
					= (CipherSuiteData)itr.next();
				log.log(Log.VERBOSE,
					LocMsg.pr("r_ssl2_cs_conf_detail",
						  d.name));
			}
		}
		if (insecCS.size() > 0) {
			log.log(Log.VERBOSE,
				LocMsg.pr("r_insec_cs_conf_hl"));
		}
		for (Iterator itr = insecCS.iterator();  itr.hasNext(); ) {
			CipherSuiteData d = (CipherSuiteData)itr.next();
			log.log(Log.VERBOSE,
				LocMsg.pr("r_insec_cs_conf", d.name));
		}
		if (unknownCS.size() > 0) {
			log.log(Log.VERBOSE,
				LocMsg.pr("r_unknown_cs_conf_hl"));
		}
		for (Iterator itr = unknownCS.iterator();
		     itr.hasNext(); ) {
			CipherSuiteData d = (CipherSuiteData)itr.next();
			log.log(Log.VERBOSE,
				LocMsg.pr("r_unknown_cs_conf", d.name));
		}
		if (probCS.size() > 0) {
			log.log(Log.VERBOSE,
				LocMsg.pr("r_prob_cs_conf_hl"));
		}
		for (Iterator itr = probCS.iterator();
		     itr.hasNext(); ) {
			CipherSuiteData d = (CipherSuiteData)itr.next();
			log.log(Log.VERBOSE,
				LocMsg.pr("r_prob_cs_conf", d.name));
		}
		if (secCS.size() > 0) {
			log.log(Log.VERBOSE,
				LocMsg.pr("r_sec_cs_conf_hl"));
		}
		for (Iterator itr = secCS.iterator();  itr.hasNext(); ) {
			CipherSuiteData d = (CipherSuiteData)itr.next();
			log.log(Log.VERBOSE,
				LocMsg.pr("r_sec_cs_conf", d.name));
		}
	}


	protected String getCertificateAlgorithmInfo(X509Certificate cert)
		throws FingerprintError {

		StringBuilder res = new StringBuilder();
		PublicKey pk = cert.getPublicKey();
		String alg = pk.getAlgorithm();

		if (pk instanceof RSAPublicKey) {
			RSAPublicKey rpk = (RSAPublicKey)pk;
			int size = rpk.getModulus().bitLength();
			res.append("RSA (");
			res.append(Integer.toString(size));
			res.append(")");

			if (opensslModHash) {
				res.append(" hash(mod): ");
			} else {
				res.append(" hash: ");
			}
			String hashVal = getRSAKeyHash(rpk);
			res.append(hashVal);
		} else if (pk instanceof DHPublicKey) {
			DHPublicKey dpk = (DHPublicKey)pk;
			int gsize = dpk.getParams().getP().bitLength();
			int lsize = dpk.getParams().getL();
			res.append("DH ("+Integer.toString(gsize)
				   +"/"+Integer.toString(lsize)+")");
		} else if (pk instanceof DSAPublicKey) {
			DSAPublicKey dpk = (DSAPublicKey)pk;
			int gsize = dpk.getParams().getP().bitLength();
			int ssize = dpk.getParams().getQ().bitLength();
			res.append("DA ("+Integer.toString(gsize)
				   +"/"+Integer.toString(ssize)+")");
		} else if (pk instanceof ECPublicKey) {
			res.append("EC Public Key");
		} else {
			res.append(alg.toString());
		}

		return res.toString();
	}


	protected void checkCertificateName(X509Certificate cert,
					                 String host) {

		boolean nameMatch = cv.checkCertificateDN(cert, host);
		boolean altMatch = cv.checkCertificateSubjAltName(cert, host);
		boolean jmatch = false;

		printSubjAltNames(cert);

		if (!nameMatch) {
			jmatch = cv.nameMatches(cert, host);
			if (Debug.get(Debug.Certs)) {
				System.err.println("Direct name mismatch "
						   +"found. Java "
						   +"hostname validator "
						   +"-> "
						   +jmatch);
			}
		}
		if (nameMatch) {
			log.log(Log.ESSENTIAL, LocMsg.pr("r_cert_CN_match"));
		} else if (altMatch) {
			log.log(Log.ESSENTIAL, LocMsg.pr("r_cert_alt_match"));
		} else if (jmatch) {
			log.log(Log.ESSENTIAL, LocMsg.pr("r_cert_match"));
		} else {
			log.log(Log.ESSENTIAL, LocMsg.pr("r_cert_mismatch"));
		}
	}


	protected void printSubjAltNames(X509Certificate cert) {
		try {
			Collection altNames =
				cert.getSubjectAlternativeNames();
			if (altNames != null) {
				log.log(Log.VERBOSE,
					LocMsg.pr("r_subalt_names"));
				for (Iterator it = altNames.iterator();
				     it.hasNext();  ) {
					String nam=it.next().toString();
					log.log(Log.VERBOSE,
						LocMsg.pr("r_altname", nam));
				}
			}
		} catch (CertificateParsingException e) {
			// Ignore
			log.log(Log.VERBOSE,
				LocMsg.pr("e_certparse_subjaltname"));
		}
	}


	protected void printX509CertificateInfo(X509Certificate cert,
						String prefix)
		throws FingerprintError {

		String subjDN =	cert.getSubjectX500Principal().getName();
		String issuerDN = cert.getIssuerX500Principal().getName();
		String sigAlg = cert.getSigAlgName();
		boolean selfSigned;
		String selfMsg = "";

		selfSigned = subjDN.equals(issuerDN);
		log.log(Log.VERBOSE,
			LocMsg.pr("r_cert_alg",
				  getCertificateAlgorithmInfo(cert),
				  (selfSigned)?LocMsg.pr("r_cert_selfsig"):"",
				  prefix)
			);
		log.log(Log.VERBOSE,
			LocMsg.pr("r_cert_subj",
				  subjDN,
				  (selfSigned)?LocMsg.pr("r_cert_same"):"",
				  prefix)
			);
		if (!selfSigned) {
			log.log(Log.VERBOSE,
				LocMsg.pr("r_cert_issuer", issuerDN, prefix));
					  
		}
		log.log(Log.VERBOSE,
			LocMsg.pr("r_cert_sigalg", sigAlg, prefix));
		log.log(Log.VERBOSE,
			LocMsg.pr("r_cert_from",
				  cert.getNotBefore().toString(), prefix));
		log.log(Log.VERBOSE,
			LocMsg.pr("r_cert_until",
				  cert.getNotAfter().toString(), prefix));
	}


	protected void publishCertificates(FingerprintResult fr)
		throws FingerprintError {

		if (fr.certs[0] instanceof X509Certificate) {
			checkCertificateName(
				    (X509Certificate)fr.certs[0], fr.host);
		}
		if (fr.certVerifies) {
			log.log(Log.ESSENTIAL, LocMsg.pr("r_cert_valid"));
		} else {
			log.log(Log.ESSENTIAL, LocMsg.pr("r_cert_invalid"));
		}

		log.log(Log.VERBOSE, LocMsg.pr("s_certchain"));
		for (int i = 0;  i < fr.certs.length;  i++) {
			if (fr.certs[i] instanceof X509Certificate) {
				X509Certificate cert =
					(X509Certificate)fr.certs[i];
				StringBuffer buf = new StringBuffer(" #");
				for (int j =
				      String.valueOf(fr.certs.length).length()
					     -String.valueOf(i).length();
				     j--> 0;  ) {
					buf.append(" ");
				}
				buf.append(Integer.toString(i));
				buf.append(":");
				printX509CertificateInfo(cert,
							 new String(buf));
			} else {
				log.log(Log.VERBOSE,
					LocMsg.pr("r_not_cert_x509"));
			}
		}
	}



}
