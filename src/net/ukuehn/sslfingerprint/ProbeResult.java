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



public class ProbeResult extends SSLResult {

	Set<String> protos;

	public ProbeResult(String theHost, int thePort,
			   Date start, Date end,
			   int supportsSSL,
			   String reason,
			   Certificate[] certificates,
			   boolean verifies,
			   boolean nameMatch) {

		super(theHost, thePort, start, end, supportsSSL, reason,
		      certificates, verifies, nameMatch);
	}


	public void setProtosResult(Set<String> supportedProtos) {
		protos = supportedProtos;
	}

}
