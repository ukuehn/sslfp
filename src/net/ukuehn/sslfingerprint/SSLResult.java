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



import java.security.cert.*;
import java.util.Date;




public class SSLResult {

	protected static final int UNKNOWN = 0;
	protected static final int UNSUPPORTED = 1;
	protected static final int SUPPORTED = 2;

	String host;
	int port;

	int sslSupport;
	String reasonNoSupport;

	boolean opensslModHash = false;

	Date startDate;
	Date endDate;

	Certificate[] certs;
	boolean certVerifies;
	boolean certNameMatch;


	public SSLResult(String theHost, int thePort,
			 Date start, Date end,
			 int supportsSSL,
			 String reason,
			 Certificate[] certificates,
			 boolean verifies,
			 boolean nameMatch) {

		host = theHost;
		port = thePort;
		startDate = start;
		endDate = end;
		sslSupport = supportsSSL;
		reasonNoSupport = reason;
		certs = certificates;
		certVerifies = verifies;
		certNameMatch = nameMatch;
	}


}
