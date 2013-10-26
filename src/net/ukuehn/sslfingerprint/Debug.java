/* -*- java -*-
 *
 * This is sslfingerprint, an fingerprinting and security analysis tool
 * for server ssl configurations.
 *
 * (C) 2010 Ulrich Kuehn <ukuehn@acm.org>
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


public class Debug {

	
	public static final int Fingerprint = 0;
	
	public static final int CollectSuites = 1;
	public static final int CheckSSLv2 = 2;
	public static final int SockInit = 3;
	public static final int Certs = 4;

	public static final int Communication = 8;
	public static final int Protocol = 9;

	public static final int Delay = 11;
	public static final int CharEncoding = 12;



	static private long debug = 0;

	static Log log;



	public static void set(long level) {
		debug = level;

		if (debug != 0) {
			System.err.println("Setting debug level "+debug);
		}

		if (Debug.get(Debug.CharEncoding)) {
			System.err.println("Debug: CharEncoding");
		}
		if (Debug.get(Debug.Delay)) {
			System.err.println("Debug: Delay");
		}
		if (Debug.get(Debug.Communication)) {
			System.err.println("Debug: Communication");
		}
		if (Debug.get(Debug.Protocol)) {
			System.err.println("Debug: Protocol");
		}
		if (Debug.get(Debug.Certs)) {
			System.err.println("Debug: Certificates");
		}
		if (Debug.get(Debug.SockInit)) {
			System.err.println("Debug: SockInit");
		}
		if (Debug.get(Debug.CheckSSLv2)) {
			System.err.println("Debug: CheckSSLv2");
		}
		if (Debug.get(Debug.CollectSuites)) {
			System.err.println("Debug: CollectSuites");
		}
		if (Debug.get(Debug.Fingerprint)) {
			System.err.println("Debug: Fingerprint");
		}
	}

	public static boolean get(int what) {
		return ((debug & (1 << what)) != 0);
	}

}