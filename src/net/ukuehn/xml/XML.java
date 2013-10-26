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

package net.ukuehn.xml;


import java.lang.StringBuilder;


public class XML {

	protected final static String critical = "<>&\"'";

	
	public static String encode(String param) {
		int n = param.length();
		StringBuilder sb = new StringBuilder(n);
		for (int i = 0;  i < n;  i++) {
			char c = param.charAt(i);
			switch (c) {
			case '"':
				sb.append("&quot;");
				break;
			case '\'':
				sb.append("&apos;");
				break;
			case '&':
				sb.append("&amp;");
				break;
			case '<':
				sb.append("&lt;");
				break;
			case '>':
				sb.append("&gt;");
				break;
			default:
				sb.append(c);
				break;
			}
		}
		return sb.toString();
	}


	public static String quote(String param) {
		return "\"" + encode(param) + "\"";
	}



	public static boolean needsEncoding(String param) {
		int n = param.length();
		for (int i = 0;  i < n;  i++) {
			if (critical.indexOf(param.charAt(i)) >= 0) {
				return true;
			}
		}
		return false;
	}

}
