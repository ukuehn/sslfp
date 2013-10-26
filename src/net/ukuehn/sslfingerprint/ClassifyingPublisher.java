/* -*- java -*-
 *
 * This is sslfingerprint, an fingerprinting and security analysis tool
 * for server ssl configurations.
 *
 * (C) 2013 Ulrich Kuehn <ukuehn@acm.org>
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

import java.util.Set;
import java.util.LinkedHashSet;
import java.util.Iterator;

import net.ukuehn.xml.*;



public class ClassifyingPublisher extends Publisher {

	Classifier cls;
	
	Set<CipherSuiteData> secCS;
	Set<CipherSuiteData> probCS;
	Set<CipherSuiteData> insecCS;
	Set<CipherSuiteData> unknownCS;


	public ClassifyingPublisher() {
		unknownCS = null;
		insecCS = null;
		probCS = null;
		secCS = null;
		cls = null;
	}


	public void classify(FingerprintResult fr) {
		if ((cls == null) || (fr == null)) {
			return;
		}
		classifyCipherSuites(fr);
	}


	public void classifyCipherSuites(FingerprintResult fr) {

		secCS = new LinkedHashSet<CipherSuiteData>();
		probCS = new LinkedHashSet<CipherSuiteData>();
		insecCS = new LinkedHashSet<CipherSuiteData>();
		unknownCS = new LinkedHashSet<CipherSuiteData>();

		if (cls == null) {
			return;
		}
		if (fr.ciphersuites == null) {
			return;
		}
		String[] protos = fr.protos.toArray(new String[0]);
		Iterator<CipherSuiteData> itr = fr.ciphersuites.iterator();
		while (itr.hasNext()) {
			CipherSuiteData d = (CipherSuiteData)itr.next();
			int res = cls.classifyCipherSuite(d, protos);
			if (res == Classification.STRENGTH_SECURE) {
				secCS.add(d);
			} else if (res ==
				   Classification.STRENGTH_PROBLEMATIC) {
				probCS.add(d);
			} else if (res == Classification.STRENGTH_INSECURE) {
				insecCS.add(d);
			} else {
				unknownCS.add(d);
			}
		}
	}


}
