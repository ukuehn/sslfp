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



import javax.security.cert.*;
import javax.net.*;
import java.net.*;
import java.io.*;


public class SocketInitialiser {

	static final int defaultPort = 443;

	protected final int defaultTimeout = 30; 

	SocketInitialiser chainedInit;


	public SocketInitialiser() {
		chainedInit = null;
	}


	public SocketInitialiser(SocketInitialiser sockInit) {
		chainedInit = sockInit;
	}


	public void setChainedInitialiser(SocketInitialiser sockInit) {
		chainedInit = sockInit;
	}


	public Socket createSocket(String host, int port)
		throws IOException, FingerprintException, FingerprintError {

		Socket s;
		if (chainedInit != null) {
			s = chainedInit.createSocket(host, port);
		} else {
			s = new Socket(host, port);
		}
		return s;
	}


	public void initSocket(Socket s)
		throws IOException, FingerprintException, FingerprintError {
		if (chainedInit != null) {
			chainedInit.initSocket(s);
		}
		/* Nothing else to do */
	}


	public void decommissionSocket(Socket s) {
		/* nothing to do here */
		if (chainedInit != null) {
			chainedInit.decommissionSocket(s);
		}
	}


	public int getDefaultPort() {
		return defaultPort;
	}


	public String getName() {
		return "Plain";
	}
}
