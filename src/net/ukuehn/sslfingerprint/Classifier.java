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



import java.io.*;



public class Classifier {


	static final String[] secureProto = {
		"SSL", "SSLv3", "TLS", "TLSv1", "TLSv1.1", "TLSv1.2"
	};
	static final String[] problemProto = {
	};
	static final String[] insecureProto = { "SSL2" };

	// Protocols susceptible for the BEAST attack, i.e. with chained
	// IV generation. This was fixed in TLS 1.1.
	// Do not include SSL2 here, as it is broken for other reasons
	// anyway.
	static final String[] protosIVProblems = {
		"SSL", "SSLv3", "TLSv1"  
	};

	static final String[] secureKex = {
		"RSA", "DHE_RSA", "DHE_DSS", "DH_RSA", "DH_DSS",
		"ECDHE_RSA", "ECDH_ECDSA", "ECDHE_ECDSA",
		"ECDH_RSA",
		"KRB5"
	};
	static final String[] problemKex = {
	};
	static final String[] insecureKex = {
		"RSA_EXPORT", "DHE_RSA_EXPORT", "DHE_DSS_EXPORT",
		"DH_RSA_EXPORT", "DH_DSS_EXPORT",
		"DH_anon", "DH_anon_EXPORT",
		"ECDH_anon",
		"KRB5_EXPORT",
		"NULL"
	};

	static final String[] secureCipher = {
		"3DES_EDE_CBC", "AES_128_CBC", "AES_256_CBC"
	};
	static final String[] problemCipher = {
		"RC4_128"
	};
	static final String[] insecureCipher = {
		"NULL", "RC2_CBC", "RC2_40_CBC", "RC2_CBC_40",
		"DES40_CBC", "DES_40_CBC", "DES_CBC_40", "DES_CBC",
		"RC4_40", "RC4_128_40"
	};

	static final String[] secureHash = {
		"MD5", "SHA", "SHA384", "SHA256"
	};
	static final String[] problemHash = {
	};
	static final String[] insecureHash = { "NULL" };

	static final String cbc = "CBC";

	//static final int STRENGTH_SECURE = 2;
	//static final int STRENGTH_PROBLEMATIC = 1;
	//static final int STRENGTH_INSECURE = 0;
	//static final int STRENGTH_UNKNOWN = -1;



	public Classifier() {
	}


	protected int classifyComponent(String c,
					String[] sec,
					String[] prob,
					String[] insec) {

		if (contains(insec, c)) {
			/* If listed in insecure, return that */
			return Classification.STRENGTH_INSECURE;
		}
		if (contains(prob, c)) {
			/* If listed in problems, return that */
			return Classification.STRENGTH_PROBLEMATIC;
		}
		if (contains(sec, c)) {
				/* If listed as secure, return that result */
				return Classification.STRENGTH_SECURE;
		}
		/*
		for (int i = 0;  i < insec.length;  i++) {
			if (c.equals(insec[i])) {
				return Classification.STRENGTH_INSECURE;
			}
		}
		for (int i = 0;  i < sec.length;  i++) {
			if (c.equals(sec[i])) {
				return Classification.STRENGTH_SECURE;
			}
		}
		*/
		return Classification.STRENGTH_UNKNOWN;
	}


	public int classifyCipherSuite(CipherSuiteData cs,
				       String[] protos) {
		boolean secure, problematic, insecure;

		int idxProto = 0;
		int idxKex = 1;
		int idxCipher = 2;
		int idxHash = 3;
		int[] res = new int[4];

		res[idxProto] = classifyComponent(cs.getProto(),
						  secureProto,
						  problemProto,
						  insecureProto);
		res[idxKex] = classifyComponent(cs.getKEX(),
						secureKex,
						problemKex,
						insecureKex);
		res[idxCipher] = classifyComponent(cs.getCipher(),
						   secureCipher,
						   problemCipher,
						   insecureCipher);
		res[idxHash] = classifyComponent(cs.getMAC(),
						 secureHash,
						 problemHash,
						 insecureHash);
		// Check if there is a problem with CBC mode, aka
		// BEAST attack ...
		if ( (res[idxCipher] == Classification.STRENGTH_SECURE)
		     && isCBCMode(cs.getCipher()) ) {
			if (hasProtoWithIVProblem(protos)) {
				res[idxCipher] =
					Classification.STRENGTH_PROBLEMATIC;
			}
		}

		secure = true;
		problematic = false;
		insecure = false;
		for (int i = 0;  i < res.length;  i++) {
			switch (res[i]) {
			case Classification.STRENGTH_SECURE:
				break;
			case Classification.STRENGTH_PROBLEMATIC:
				secure = false;
				problematic = true;
				break;
			case Classification.STRENGTH_INSECURE:
				secure = false;
				insecure = true;
				break;
			default: // its apparently unknown, so break out here
				return Classification.STRENGTH_UNKNOWN;
			}
		}
		if (insecure) {
			return Classification.STRENGTH_INSECURE;
		} else if (problematic) {
			return Classification.STRENGTH_PROBLEMATIC;
		} else if (secure) {
			return Classification.STRENGTH_SECURE;
		} else {
			return Classification.STRENGTH_UNKNOWN;
		}
	}


	public int classifyCipherSuite(CipherSuiteData cs) {
		// this classifier ignores the protos
		return classifyCipherSuite(cs, null);
	}


	public int classifyProto(String proto) {
		return classifyComponent(proto,
					 secureProto,
					 problemProto,
					 insecureProto);
	}


	public int classifyProto(String proto, CipherSuiteData[] suites) {
		// ignore the suites for this classifier
		return classifyComponent(proto,
					 secureProto,
					 problemProto,
					 insecureProto);
	}

	protected boolean hasProtoWithIVProblem(String[] protos) {
		if (protos == null) {
			return false;
		}
		for (int i = 0;  i < protos.length;  i++) {
			if (contains(protosIVProblems, protos[i])) {
				return true;
			}
		}
		return false;
	}

	protected boolean isCBCMode(String cipherName) {
		if (cipherName == null) {
			return false;
		}
		return cipherName.toUpperCase().contains(cbc);
	}

	protected boolean contains(String[] hay, String needle) {
		if (hay == null) {
			return false;
		}
		for (int i = 0;  i < hay.length;  i++) {
			if (hay[i].equals(needle)) {
				return true;
			}
		}
		return false;
	}

				
}
