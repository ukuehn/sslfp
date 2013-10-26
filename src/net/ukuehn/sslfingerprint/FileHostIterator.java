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
import java.util.Iterator;
import java.util.StringTokenizer;



public class FileHostIterator implements Iterator<Host> {

	BufferedReader bReader;
	Host nextHost;
	boolean done;
	int defPort;

	protected FileHostIterator(BufferedReader reader, int defaultPort) {
		bReader = reader;
		nextHost = null;
		done = false;
		defPort = defaultPort;
	}


	public static Iterator<Host> getInstance(String fileName,
						 int defaultPort)
		throws IOException {

		BufferedReader br;
		if (fileName.equals("-")) {
			InputStreamReader ir
				= new InputStreamReader(System.in);
			br = new BufferedReader(ir);
		} else {
			FileReader fr = new FileReader(fileName);
			br = new BufferedReader(fr);
		}
		return new FileHostIterator(br, defaultPort);
	}


	public void remove() {
		throw new UnsupportedOperationException();
	}


	public boolean hasNext()
		throws IllegalArgumentException {
		if (done) {
			return false;
		}
		if (nextHost != null) {
			return true;
		}
		while (!done && (nextHost == null)) {
			try {
				String hostStr = bReader.readLine();
				if (hostStr == null) {
					break;
				}
				nextHost = Host.parse(hostStr, defPort);
			} catch (IOException e) {
				try {
					bReader.close();
				} catch (IOException e0) {
					// ignore
				}
				done = true;
			}
		}
		return (!done && (nextHost != null));
	}


	public Host next() {
		Host res = nextHost;
		nextHost = null;
		return res;
	}

}
