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


import java.util.Date;
import java.util.Set;




public class FingerprintResult extends SSLResult {

	Set<String> protos;
	Set<CipherSuiteData> ciphersuites;
	Set<CipherSuiteData> sslv2CS;

	boolean supportsSSLv2;
	int sslv2Behavior;



	public FingerprintResult(String theHost, int thePort,
				 Date start, Date end,
				 int supportsSSL,
				 String reason,
				 Certificate[] certificates,
				 boolean verifies,
				 boolean nameMatch) {

		super(theHost, thePort, start, end, supportsSSL, reason,
		      certificates, verifies, nameMatch);
		protos = null;
		ciphersuites = null;
		sslv2CS = null;
	}


	public void setProtosResult(Set<String> supportedProtos,
				    boolean sslv2Support, int behaviorSSLv2) {
		protos = supportedProtos;
		supportsSSLv2 = sslv2Support;
		sslv2Behavior = behaviorSSLv2;
	}


	public void setCiphersuiteResult(Set<CipherSuiteData> supportedCS,
					 Set<CipherSuiteData> ssl2CS) {
		ciphersuites = supportedCS;
		sslv2CS = ssl2CS;
	}


}
