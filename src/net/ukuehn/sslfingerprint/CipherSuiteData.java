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



//import java.io.*;



public class CipherSuiteData {

	String name;
	String proto;
	String hash;
	String kex;
	String cipher;
	final static String kexSep = "_WITH_";


	public CipherSuiteData(String theName) {
		name = theName;
		extractParts();
	}


	public CipherSuiteData(String theName, String theProto) {
		name = theName;
		extractParts();
		proto = theProto;
	}


	public String getProto() {
		return proto;
	}


	public String getKEX() {
		return kex;
	}


	public String getCipher() {
		return cipher;
	}


	public String getMAC() {
		return hash;
	}



	/* The string representation of a cipher suite is
	 * proto_kex_WITH_cipher_hash
	 * where
	 *     proto is the handshake proto
	 *     kex is the key exchange algorithm
	 *     cipher is the confidentiality algorithm
	 *     hash is the hash function for message integrity
	 */
	protected void extractParts() {
		int idx;
		StringBuffer s = new StringBuffer(name);
		
		idx = s.indexOf("_");
		if (idx >= 0) {
			proto = s.substring(0, idx);
			s.delete(0, idx+1);
		}
		idx = s.indexOf(kexSep);
		if (idx >= 0) {
			kex = s.substring(0, idx);
			s.delete(0, idx+kexSep.length());
			idx = s.lastIndexOf("_");
			cipher = s.substring(0, idx);
			hash = s.substring(idx+1);
		} else {
			// There is a ciphersuite named
			// TLS_EMPTY_RENEGOTIATION_INFO_SCSV
			// which has to be handled separately
			idx = s.indexOf("_");
			if (idx >= 0) {
				kex = s.substring(0, idx);
				s.delete(0, idx+1);
			}
			cipher = s.toString();
			hash = "";
		}
	}


}
