/* -*- java -*-
 *
 * (C) 2013 Ulrich Kuehn <ukuehn@acm.org>
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



public class Classification {

	static final int STRENGTH_SECURE = 2;
	static final int STRENGTH_PROBLEMATIC = 1;
	static final int STRENGTH_INSECURE = 0;
	static final int STRENGTH_UNKNOWN = -1;

	int strength;
	String reason;


	public Classification() {
		strength = STRENGTH_UNKNOWN;
		reason = new String();
	}


	public int getStrength() {
		return strength;
	}


	public String getReason() {
		return reason;
	}

}
