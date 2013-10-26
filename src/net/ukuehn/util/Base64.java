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


package net.ukuehn.util;



public class Base64 {


	private static String encodeTab =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"+
		"abcdefghijklmnopqrstuvwxyz"+
		"0123456789+/";
	private static int[] decodeTab = null;

	public static String encode(String val) {
		int len = val.length();
		StringBuffer res = new StringBuffer();
		int val0, val1, val2;
		int idx0, idx1, idx2, idx3;
		
		for (int i = 0;  i < len-2;  i += 3) {
			val0 = (int)val.charAt(i);
			val1 = (int)val.charAt(i+1);
			val2 = (int)val.charAt(i+2);
			
			idx0 = (val0 >> 2) & 0x3f;
			idx1 = ((val0 << 4) & 0x30)
				| ((val1 >> 4) & 0x0f);
			idx2 = ((val1 << 2) & 0x3c)
				| ((val2 >> 6) & 0x03);
			idx3 = (val2 & 0x3f);

			res.append(encodeTab.charAt(idx0));
			res.append(encodeTab.charAt(idx1));
			res.append(encodeTab.charAt(idx2));
			res.append(encodeTab.charAt(idx3));
		}

		switch (len % 3) {
		case 2:
			val0 = (int)val.charAt(len-2);
			val1 = (int)val.charAt(len-1);
			idx0 = (val0 >> 2) & 0x3f;
			idx1 = ((val0 << 4) & 0x30)
				| ((val1 >> 4) & 0x0f);
			idx2 = ((val1 << 2) & 0x3c);
			res.append(encodeTab.charAt(idx0));
			res.append(encodeTab.charAt(idx1));
			res.append(encodeTab.charAt(idx2));
			res.append('=');
			break;
		case 1:
			val0 = (int)val.charAt(len-1);
			idx0 = (val0 >> 2) & 0x3f;
			idx1 = ((val0 << 4) & 0x30);
			res.append(encodeTab.charAt(idx0));
			res.append(encodeTab.charAt(idx1));
			res.append('=');
			res.append('=');
		case 0:
			break;
		}

		return res.toString();
	}

	public static String decode(String val) {
		if (decodeTab == null) {
			initDecode();
		}
		return "";
	}

	private static void initDecode() {
		decodeTab = new int[128];
		for (int i = 0;  i < 128;  i++) {
			decodeTab[i] = -1;
		}
		for (int i = 0;  i < encodeTab.length();  i++) {
			char c = encodeTab.charAt(i);
			int idx = (int)c;
			decodeTab[idx] = i;
		}
	}


	public static void main(String args[]) {

		String[] clear = {
			"testdata",
			"aaa",
			"012345"
		};
		
		String[] expected = {
			"dGVzdGRhdGE=",
			"YWFh",
			"MDEyMzQ1"
		};

		boolean ok;
		String res;

		ok = true;
		for (int i = 0;  i < clear.length;  i++) {
			res = Base64.encode(clear[i]);
			System.out.print("'"+clear[i]+"' --> '"
					 +res+"' ");
			if (res.equals(expected[i])) {
				System.out.println("OK");
			} else {
				System.out.println("Failed");
			}
		}
	}


}
