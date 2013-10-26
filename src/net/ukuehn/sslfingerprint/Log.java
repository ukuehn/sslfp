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



public class Log {

	protected PrintWriter out;
	protected int logLevel;

	/* Only the most important output */
	public final static int ESSENTIAL = 0;

	/* Verbose output on normal operation */
	public final static int VERBOSE = 1;


	public Log() {
		out = new PrintWriter(System.out);
		logLevel = 0;
	}


	public void setLogLevel(int level) {
		logLevel = level;
	}


	public int getLogLevel() {
		return logLevel;
	}


	public void close() {
		out.flush();
		out.close();
	}


	public void log(int level, String msg) {
		if (level > logLevel) {
			return;
		}
		out.println(msg);
		out.flush();
	}


	public void log(String msg) {
		log(0, msg);
	}


}
