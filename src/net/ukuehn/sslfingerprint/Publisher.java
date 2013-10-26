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

import net.ukuehn.xml.*;
import net.ukuehn.security.CertValidator;



public class Publisher {

	boolean opensslModHash;
	CertValidator cv;


	public Publisher() {
		opensslModHash = false;
		cv = null;
	}


	public void setUseModHash(boolean useModHash) {
		opensslModHash = useModHash;
	}


	public void setCertValidator(CertValidator validator) {
		cv = validator;
	}


	public void publishHeader() throws IOException, FingerprintError {
		// nothing
	}


	public void publishFooter() throws IOException, FingerprintError {
		// nothing
	}


	public void publish(SSLResult sr)
		throws IOException, FingerprintError {
		// nothing
	}



	/*
	 * Here are some methods for use by subclasses
	 */

	/* Format a string in the way OpenSSL formats the RSA modulus
	 * in order to compute a hash of the modulus in the same way.
	 * The format is
	 *          Modulus=......\n
	 */
	protected String formatOpenSSLModulus(byte[] data) {
		String hexchar = "0123456789ABCDEF";
		StringBuilder sb = new StringBuilder();
		sb.append("Modulus=");
		if (data == null) {
			return sb.toString();
		}
		int start;
		for (start = 0;  start < data.length;  start++) {
			if (data[start] != 0) {
				break;
			}
		}
		for (int i = start;  i < data.length;  i++) {
			int hi = (data[i] >> 4) & 0x0f;
			int lo = data[i] & 0x0f;
			sb.append(hexchar.charAt(hi));
			sb.append(hexchar.charAt(lo));
		}
		sb.append("\n");
		return sb.toString();
	}


	/* Compute the SHA-1 hash of the key. Depending on the value
	 * of opensslModHash format the hash input like OpenSSL, otherwise
	 * use length, exponent and modulus as input.
	 */
	protected String getRSAKeyHash(RSAPublicKey rpk)
		throws FingerprintError {
		StringBuilder res = new StringBuilder(40); // sha1 hash

		int size = rpk.getModulus().bitLength();
		byte[] modbytes = rpk.getModulus().toByteArray();
		byte[] expbytes = rpk.getPublicExponent().toByteArray();
		int len = expbytes.length;
		byte[] lenbytes;
		if (len < 255) {
			lenbytes = new byte[1];
			lenbytes[0] = (byte)(len & 0xff);
		} else {
			lenbytes = new byte[3];
			lenbytes[0] = 0;
			lenbytes[1] = (byte)((len >> 8) & 0xff);
			lenbytes[2] = (byte)(len & 0xff);
		}
		try {
			MessageDigest md =
				MessageDigest.getInstance("SHA");
			if (opensslModHash) {
				String ms =
					formatOpenSSLModulus(modbytes);
				//System.err.println("mod hash:"+ms);
				md.update(ms.getBytes());
			} else {
				md.update(lenbytes);
				md.update(expbytes);
				md.update(modbytes);
			}
			byte[] digest = md.digest();
			String hexchar = "0123456789abcdef";
			for (int i = 0;  i < digest.length;  i++) {
				int hi = (digest[i] >> 4) & 0x0f;
				int lo = digest[i] & 0x0f;
				res.append(hexchar.charAt(hi));
				res.append(hexchar.charAt(lo));
			}
		} catch (NoSuchAlgorithmException e) {
			throw new InstallationError(
				    "SHA-1 algorithm not available", e);
		}
		return res.toString();
	}


}
