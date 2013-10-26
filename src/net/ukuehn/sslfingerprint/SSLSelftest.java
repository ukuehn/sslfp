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




public class SSLSelftest {


	/* Run through all supported ciphersuites of the installation
	 * and check that the classifier in class Classifier does never
	 * return Classification.STRENGTH_UNKNOWN.
	 */
	public static boolean selfTest() {

		Classifier cls = new Classifier();
		SSLSocketFactory f
			= (SSLSocketFactory)SSLSocketFactory.getDefault();
		String[] supported = f.getSupportedCipherSuites();

		for (int i = 0;  i < supported.length;  i++) {
			if (supported[i].equals(
			       "TLS_EMPTY_RENEGOTIATION_INFO_SCSV")) {
				continue;
			}
			CipherSuiteData d = new CipherSuiteData(supported[i]);
			if (cls.classifyCipherSuite(d) 
			    == Classification.STRENGTH_UNKNOWN) {
				return false;
			}
		}
		return true;
	}


	public static void loggingSelfTest(Log log, Classifier sc,
					   String header) {
		Classifier cls = sc;
		SSLSocketFactory f
			= (SSLSocketFactory)SSLSocketFactory.getDefault();
		String[] supported = f.getSupportedCipherSuites();

		if (cls == null) {
			sc = new Classifier();
		}
		if (header != null) {
			log.log(Log.ESSENTIAL, header);
		}
		log.log(Log.ESSENTIAL, LocMsg.pr("r_selftest_header2"));
		for (int i = 0;  i < supported.length;  i++) {
			if (supported[i].equals(
			       "TLS_EMPTY_RENEGOTIATION_INFO_SCSV")) {
				continue;
			}
			CipherSuiteData d = new CipherSuiteData(supported[i]);
			int res = cls.classifyCipherSuite(d);
			if (res == Classification.STRENGTH_SECURE) {
				log.log(Log.ESSENTIAL,
					LocMsg.pr("r_sec_cs_conf",
						  d.name));
			} else if (res==Classification.STRENGTH_PROBLEMATIC){
				log.log(Log.ESSENTIAL,
					LocMsg.pr("r_prob_cs_conf",
						  d.name));
			} else if (res == Classification.STRENGTH_INSECURE) {
				log.log(Log.ESSENTIAL,
					LocMsg.pr("r_insec_cs_conf",
						  d.name));
			} else {
				log.log(Log.ESSENTIAL,
					LocMsg.pr("r_unknown_cs_conf",
						  d.name));
			}
		}
	}	

}
