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

import java.util.StringTokenizer;
import java.util.regex.Pattern;
import java.util.regex.Matcher;


public class Host {

	public String name;
	public int port;

	public Host(String hostName, int portNo) {
		name = hostName;
		port = portNo;
	}


	protected static boolean looksLikeIPv6(String hostStr) {
		int first, last, dcol;

		first = hostStr.indexOf(':');
		last = hostStr.lastIndexOf(':');
		dcol = hostStr.indexOf("::");

		if ( (first != last) ||
		     (dcol != -1) ) {
			return true;
		}
		return false;
	}

	protected static Host parseNoIPv6(String hostStr, int defaultPort)
		throws IllegalArgumentException {
		//		throws NumberFormatException {

		StringTokenizer st;
		String parsedName;
		int port;

		st = new StringTokenizer(hostStr, ":");
		if (!st.hasMoreTokens()) {
			return null;
		}
		parsedName = st.nextToken();
		port = defaultPort; // set just in case...
		if (st.hasMoreTokens()) {
			String sPort = st.nextToken();
			try {
				port = Integer.parseInt(sPort);
			} catch (NumberFormatException e) {
				//throw new NumberFormatException(
				throw new IllegalArgumentException(
					      LocMsg.pr("e_port_num", sPort)
					      );
			}
		}
		return new Host(parsedName, port);
	}


	protected static Pattern ipv6pattern
		= Pattern.compile("^\\[([0-9:A-Fa-f]+)\\](?::(\\d{1,5}+))?$");

	protected static Host parseIPv6(String hostStr, int defaultPort)
		throws IllegalArgumentException {

		Matcher m = ipv6pattern.matcher(hostStr);
		if (!m.matches()) {
			throw new IllegalArgumentException(
					  LocMsg.pr("e_ipv6_format", hostStr)
					  );
		}
		String parsedName = m.group(1);
		String sPort = m.group(2);
		int port = defaultPort; // set just in case...
		if (sPort != null) {
			try {
				port = Integer.parseInt(sPort);
			} catch (NumberFormatException e) {
				throw new IllegalArgumentException(
					      LocMsg.pr("e_port_num", sPort)
					      );
			}
		}
		return new Host(parsedName, port);
	}


	public static Host parse(String hostStr, int defaultPort)
		throws IllegalArgumentException {
		
		if (hostStr == null) {
			return null;
		}
		if (looksLikeIPv6(hostStr)) {
			return parseIPv6(hostStr, defaultPort);
		} else {
			return parseNoIPv6(hostStr, defaultPort);
		}
	}


}
