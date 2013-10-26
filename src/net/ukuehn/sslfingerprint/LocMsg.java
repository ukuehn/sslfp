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



import java.io.*;
import java.util.Properties;
import java.util.ResourceBundle;
import java.text.MessageFormat;


public class LocMsg {

	private static LocMsg theInstance = new LocMsg();


	private ResourceBundle resources;


	private LocMsg() {
		resources = ResourceBundle.getBundle("messages");
		if (Debug.get(Debug.CharEncoding)) {
			String t = "Teststring: äöü";
			System.err.println("Default encoding: "
				 +java.nio.charset.Charset.defaultCharset()
					   );

			System.err.println(t);
			System.err.println(hexBytes(t));
			System.err.println(getStringResource("d_testprop"));
			System.err.println(
				hexBytes(getStringResource("d_testprop"))
				);
		}
	}


	private String getStringResource(String rs) {
		String res = resources.getString(rs);
		if (res == null) {
			throw new RuntimeException("Unknown resource: '"
						   +rs+"'");
		}
		return res;
	}


	private String pr(String rs, Object[] params) {
		String templ = getStringResource(rs);
		return MessageFormat.format(templ, params);
	}


	public static String pr(String rs) {
		return theInstance.getStringResource(rs);
	}


	public static String pr(String rs, String param) {
		Object[] params = { param };
		return theInstance.pr(rs, params);
	}


	public static String pr(String rs, String param0, String param1) {
		Object[] params = { param0, param1 };
		return theInstance.pr(rs, params);
	}


	public static String pr(String rs, String p0, String p1, String p2) {
		Object[] params = { p0, p1, p2 };
		return theInstance.pr(rs, params);
	}


	public static String pr(String rs,
				String p0, String p1,
				String p2, String p3) {
		Object[] params = { p0, p1, p2, p3 };
		return theInstance.pr(rs, params);
	}


	public static String pr(String rs,
				String p0, String p1,
				String p2, String p3,
				String p4, String p5, String p6) {
		Object[] params = { p0, p1, p2, p3, p4, p5, p6 };
		return theInstance.pr(rs, params);
	}


	public static String pr(String rs,
				String p0, String p1,
				String p2, String p3,
				String p4, String p5,
				String p6, String p7, String p8) {
		Object[] params = { p0, p1, p2, p3, p4, p5, p6, p7, p8 };
		return theInstance.pr(rs, params);
	}


	private String hexBytes(String s) {
		byte[] b = s.getBytes();
		String res = "("+b.length+" Bytes) ";

		for (int i = 0;  i < b.length;  i++) {
			res += Integer.toHexString(b[i] & 0xff) + " ";
		}
		return res;
	}

}