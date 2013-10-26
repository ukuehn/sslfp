/* -*- java -*-
 *
 * (C) 2012 Ulrich Kuehn <ukuehn@acm.org>
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
 *
 */

/* This is a trust manager that does accept all certificate chains, thus
 * effectivly disables certificate validation.
 * Inspired by
 *   http://exampledepot.com/egs/javax.net.ssl/TrustAll.html
 */

package net.ukuehn.security;


import javax.net.ssl.*;
import java.security.cert.*;
import javax.security.auth.*;

import javax.net.*;
import java.net.*;
import java.io.*;


public class NullTrustManager implements X509TrustManager {

	static final X509Certificate[] acceptedIssuers =
		new X509Certificate[0];

	public X509Certificate[] getAcceptedIssuers() {
		return acceptedIssuers;
	}

	public void checkClientTrusted(X509Certificate[] certs,
				       String authType) {
	}

	public void checkServerTrusted(X509Certificate[] certs,
				       String authType) {
	}

}
