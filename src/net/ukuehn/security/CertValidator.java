/* -*- java -*-
 *
 * This is sslfingerprint, an fingerprinting and security analysis tool
 * for server ssl configurations.
 *
 * (C) 2010, 2012, 2013 Ulrich Kuehn <ukuehn@acm.org>
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

package net.ukuehn.security;


import javax.net.ssl.*;
import javax.security.auth.*;
import javax.net.*;
import javax.crypto.interfaces.*;
import java.security.cert.*;
import java.security.cert.X509Certificate;
import java.net.*;
import java.io.*;

import java.security.interfaces.*;
import java.security.KeyStore;

import java.security.NoSuchAlgorithmException;
import java.security.KeyStoreException;

import java.util.Collection;
import java.util.Iterator;

import sun.security.util.HostnameChecker;

import net.ukuehn.sslfingerprint.FingerprintError;
import net.ukuehn.sslfingerprint.InstallationError;
import net.ukuehn.sslfingerprint.Debug;
import net.ukuehn.sslfingerprint.LocMsg;


public class CertValidator {

	X509TrustManager tm = null;
	KeyStore ks = null;

	HostnameChecker hnc;


	public CertValidator() {
		tm = null;
		ks = null;
		hnc = HostnameChecker.getInstance(HostnameChecker.TYPE_TLS);
	}


	public void init() throws FingerprintError {
		/*
		 * Load the default trust store, make use of system properties
		 * if they are set. See also
		 * http://download.oracle.com/javase/1.5.0/
		 *      docs/guide/security/jsse/JSSERefGuide.html#TrustManager
		 * http://stackoverflow.com/questions/9552725/
		 *      add-truststore-for-client-authentication
		 * and openjdk-
		 *    jdk/test/lib/security/cacerts/VerifyCACerts.java
		 * 
		 */

		String sep = System.getProperty("file.separator");
		String cacertsFileName =
			System.getProperty("java.home") + sep + "lib"
			+ sep + "security" + sep + "cacerts";
		String propsCaCertsFileName =
			System.getProperty("javax.net.ssl.trustStore");
		String ksPassword = "changeit";
		String propPW =
			System.getProperty("javax.net.ssl.trustStorePassword");

		if (propsCaCertsFileName != null) {
			cacertsFileName = propsCaCertsFileName;
		}
		if (propPW != null) {
			ksPassword = propPW;
		}
		if (Debug.get(Debug.Certs)) {
			System.err.println("CertValidator.init: "
					   +"Loading Truststore from "
					   +cacertsFileName);
			System.err.println("CertValidator.init: "
					   +"Truststore password: "
					   +ksPassword);
		}

		FileInputStream ksFileInp = null;
		try {
			ksFileInp = new FileInputStream(cacertsFileName);
		} catch (FileNotFoundException e) {
			throw new InstallationError(e);
		}
		try {
			ks = KeyStore.getInstance("JKS");
			ks.load(ksFileInp, ksPassword.toCharArray());
			//ks.load(new FileInputStream("cacerts"),
			//	"".toCharArray());
		} catch (KeyStoreException e) {
			throw new InstallationError(e);
		} catch (NoSuchAlgorithmException e) {
			throw new InstallationError(e);
		} catch (CertificateException e) {
			throw new InstallationError(e);
		} catch (IOException e) {
			throw new InstallationError(e);
		}

		String alg = TrustManagerFactory.getDefaultAlgorithm();
		if (Debug.get(Debug.Certs)) {
			System.err.println("CertValidator.init(): "
				+"TrustManagerFactory default algorithm is "
				+alg);
		}

		try {
			TrustManagerFactory tmf
				= TrustManagerFactory.getInstance(alg);
			tmf.init(ks);

			TrustManager[] allTM = tmf.getTrustManagers();
			for (int i = 0;  i < allTM.length;  i++) {
				if (allTM[i] instanceof X509TrustManager) {
					tm = (X509TrustManager)allTM[i];
					if (Debug.get(Debug.Certs)) {
						System.err.println(
						   "CertValidator.init(): "
						  +"Found X509TrustManager");
					}
					break;
				}
			}
		} catch (NoSuchAlgorithmException e) {
			throw new
			    InstallationError(LocMsg.pr("e_trustmanager"), e);
		} catch (KeyStoreException e) {
			throw new InstallationError(e);
		}

	}


	public boolean isValidChain(X509Certificate[] x509certs,
				    String authType) {

		boolean valid = false;

		try {
			tm.checkServerTrusted(x509certs, authType);
			valid = true;
		} catch (CertificateException e) {
			 if (Debug.get(Debug.Certs)) {
				 System.err.println(
				      "CertValidator.isValidChain: "
				      +e.getMessage());
			 }
			 // Ignore exception, default return value is false
		}
		return valid;
	}
	

	public boolean isValidChain(Certificate[] certs, String authType) {

		boolean valid = false;
		X509Certificate[] x509certs
			= new X509Certificate[certs.length];
		try {
			for (int i = 0;  i < certs.length;  i++) {
				if (certs[i] instanceof X509Certificate) {
					x509certs[i] =
						(X509Certificate)certs[i];
				} else {
					throw new CertificateException(
						   "Not a X509 Certificate:"
						   +certs[i].toString());
				}
			}
			return isValidChain(x509certs, authType);
		} catch (CertificateException e) {
			if (Debug.get(Debug.Certs)) {
				System.err.println(
				      "CertValidator.isValidChain: "
				      +e.getMessage());
			}
			return false;
		}
	}


	public boolean nameMatches(X509Certificate xcert, String hostname) {

		boolean result = false;
		
		try {
			hnc.match(hostname, xcert);
			result = true;
		} catch (CertificateException e) {
			// ignore, default return value is false
		}
		return result;
	}


	public boolean nameMatches(Certificate cert, String hostname) {

		boolean result = false;
		X509Certificate xcert;

		try {
			if (cert instanceof X509Certificate) {
				xcert = (X509Certificate)cert;
			} else {
				throw new CertificateException(
					 "Not a X509Certificate: "
					 +cert.toString());
			}
			hnc.match(hostname, xcert);
			result = true;
		} catch (CertificateException e) {
			// ignore, default return value is false
		}
		return result;
	}


	public boolean checkCertificateDN(X509Certificate cert,
				                       String host) {

		String foundDN = cert.getSubjectDN().getName();
		String expectedDN = "CN="+host;
		String foundDNLower = foundDN.toLowerCase();
		String expectedDNLower = expectedDN.toLowerCase();
		boolean nameMatch
			= (foundDNLower.indexOf(expectedDNLower) >= 0);
		return nameMatch;
	}


	public boolean checkCertificateSubjAltName(X509Certificate cert,
				                             String host) {

		boolean altMatch = false;

		try {
			Collection altNames =
				cert.getSubjectAlternativeNames();
			String expNam = host.toLowerCase();
			if (altNames != null) {
				for (Iterator it = altNames.iterator();
				     it.hasNext();  ) {
					String nam=it.next().toString();
					String lnam = nam.toLowerCase();

					// BUG: must not be substring in name
					// need to parse string and check
					// full name
					if (lnam.indexOf(expNam) >= 0) {
						altMatch = true;
					}
				}
			}
		} catch (CertificateParsingException e) {
			// Ignore, default return value is false
		}
		return altMatch;
	}


}
