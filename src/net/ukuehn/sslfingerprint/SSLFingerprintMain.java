/* -*- java -*-
 *
 * This is sslfingerprint, an fingerprinting and security analysis tool
 * for server ssl configurations.
 *
 * (C) 2010-2013 Ulrich Kuehn <ukuehn@acm.org>
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


import java.net.*;
import java.io.*;

import java.security.interfaces.*;
import java.security.PublicKey;
import java.security.KeyStore;
import java.security.MessageDigest;

import java.security.NoSuchAlgorithmException;
import java.security.KeyStoreException;

import java.util.Date;
import java.util.LinkedList;
import java.util.Iterator;
import java.util.ListIterator;
import java.util.StringTokenizer;
import java.text.SimpleDateFormat;

import net.ukuehn.xml.SimpleXMLWriter;
import net.ukuehn.security.CertValidator;


public class SSLFingerprintMain {

	static final String progname="SSLFingerprint";
	static final String version = "0.9.7a";
	static final String prompt = progname+" v"+version
		+" by Ulrich Kuehn <ukuehn@acm.org>";
	
	static final int defaultPort = 443;


	static void usage() {
		System.err.println(LocMsg.pr("s_usage", version));
		System.exit(1);
	}


	static HttpProxySocketInitialiser getProxyInitialiser(String proxyArg)
		throws NumberFormatException {

		String proxyHost = null;
		String sProxyPort =null ;
		int pport;
		String id = null;
		String pw = null;
		HttpProxySocketInitialiser pi = null; /* proxy initialiser */
		StringTokenizer st;

		if (proxyArg == null) {
			return null;
		}

		/* Try to parse [uid[:pw]@]host[:port], but if the
		 * user part uid[:pw] is empty, accept also
		 * host[:port[:uid[:pw]]]
		 */
		st = new StringTokenizer(proxyArg, "@");
		String hostPart = null;
		String userPart = null;
		if (st.hasMoreTokens()) {
			hostPart = st.nextToken();
		}
		if (st.hasMoreTokens()) {
			// hostPart is actually userPart
			// so shift it
			userPart = hostPart;
			hostPart = st.nextToken();
		}

		st = new StringTokenizer(hostPart, ":");
		if (st.hasMoreTokens()) {
			proxyHost = st.nextToken();
		}
		if (st.hasMoreTokens()) {
			sProxyPort = st.nextToken();
		}

		if (userPart != null) {
			st = new StringTokenizer(userPart, ":");
		}

		/* Common part to parse uid[:pw] part, either from
		 * left of an @, or from right of host:port
		 */
		if (st.hasMoreTokens()) {
			id = st.nextToken();
		}
		if (st.hasMoreTokens()) {
			pw = st.nextToken();
		}

		pport = HttpProxySocketInitialiser.defaultPort;
		if (sProxyPort != null) {
			try {
				pport = Integer.parseInt(sProxyPort);
			} catch (NumberFormatException e) {
				throw new NumberFormatException(
				      LocMsg.pr("e_proxy_port_num",
						sProxyPort) );
			}
		}
		pi = new HttpProxySocketInitialiser(proxyHost, pport);
		if (id != null) {
			pi.setCredentials(id, pw);
		}
		return pi;
	}


	static SocketInitialiser getSocketInitialiserFromProto(String proto) {

		SocketInitialiser si = null;

		if (proto.equals("plain")) {
			si = new SocketInitialiser();
		} else if (proto.equals("smtp")) {
			si = new SmtpSocketInitialiser();
		} else if (proto.equals("pop3")) {
			si = new Pop3SocketInitialiser();
		} else if (proto.equals("imap")) {
			si = new ImapSocketInitialiser();
		}
		return si;
	}


	static Iterator<Host> getHostsFromCmdLine(String args[],
						  int startArg,
						  int defaultPort)
		throws NumberFormatException {

		LinkedList<Host> hostList = new LinkedList<Host>();
		for (int nextarg = startArg;
		     nextarg < args.length;  nextarg++) {

			Host host = Host.parse(args[nextarg], defaultPort);
			if (host == null) {
				usage();
			}
			hostList.add(host);
		}
		return hostList.listIterator();
	}


	public static void main(String args[])
		throws IOException, Exception {

		SocketInitialiser si = null;
		HttpProxySocketInitialiser pi = null; /* proxy initialiser */
		Iterator<Host> hosts;
		Log log;

		int nextopt;
		boolean portArg = false;
		int debug = 0; 

		String optArgProxy = null;
		String optArgProto = null;
		String optArgDebug = null;
		String optArgListFile = null;
		String optArgDelay = null;
		boolean optModHash = false;
		boolean optCheckOnly = false;
		boolean optXML = false;
		boolean optself = false;
		boolean optKerb = false;
		boolean optAllSupported = false;
		int optVerbLevel = 0;
		int port;
		int delay = 0;
		CertValidator cv;
		Classifier sc;

		nextopt = 0;
		port = defaultPort;
		for (nextopt = 0;  nextopt < args.length;  nextopt++) {

			/* handle options here */
			if (!args[nextopt].startsWith("-")) {
				break;
			}
			if (args[nextopt].equals("-V")
			    || args[nextopt].equals("-h")
			    || args[nextopt].equals("-?")) {
				usage();
			} else if (args[nextopt].equals("-c")) {
				optCheckOnly = true;
			} else if (args[nextopt].equals("-x")) {
				optXML = true;
			} else if (args[nextopt].equals("-v")) {
				optVerbLevel += 1;
			} else if (args[nextopt].equals("-m")) {
				optModHash = true;
			} else if (args[nextopt].equals("-k")) {
				optKerb = true;
			} else if (args[nextopt].equals("-a")) {
				optAllSupported = true;
			} else if (args[nextopt].equals("-p")) {
				nextopt++;
				if (nextopt < args.length) {
					optArgProto = args[nextopt];
				}
			} else if (args[nextopt].equals("-P")) {
				nextopt++;
				optArgProxy = args[nextopt];
			} else if (args[nextopt].equals("-f")) {
				nextopt++;
				optArgListFile = args[nextopt];
			} else if (args[nextopt].equals("-D")) {
				nextopt++;
				optArgDebug = args[nextopt];
			} else if (args[nextopt].equals("-d")) {
				nextopt++;
				optArgDelay = args[nextopt];
			} else if (args[nextopt].equals("-T")) {
				optself = true;
			} else {
				/* Wrong option given */
				usage();
			}
		}


		log = new Log();
		log.setLogLevel(optVerbLevel);
		BufferedWriter out = new BufferedWriter(
					   new PrintWriter(System.out));
		SimpleXMLWriter xw = new SimpleXMLWriter(out);
		if (optArgDebug != null) {
			try {
				debug = Integer.parseInt(optArgDebug);
				Debug.set(debug);
			} catch (NumberFormatException e) {
				System.err.println(LocMsg.pr("e_debug_level",
							     optArgDebug)
						   );
				System.exit(-1);
			}
		}

		cv = new CertValidator();
		cv.init();
		sc = new Classifier();

		if (!SSLSelftest.selfTest()) {
			if (optself) {
				SSLSelftest.loggingSelfTest(log, sc,
					      LocMsg.pr("r_selftest_header"));
			} else {
				log.log(LocMsg.pr("r_hint_unknown"));
			}
		} else {
			if (optself) {
				SSLSelftest.loggingSelfTest(log, sc, null);
			}
		}


		if (optArgDelay != null) {
			try {
				delay = Integer.parseInt(optArgDelay);
			} catch (NumberFormatException e) {
				System.err.println(LocMsg.pr("w_delay_number",
							     optArgDelay));
				delay = 0;
			}
			if (Debug.get(Debug.Delay)) {
				System.err.println("Setting delay to "
						   +String.valueOf(delay)
						   +" msec.");
			}
		}

		if (optArgProto != null) {
			si = getSocketInitialiserFromProto(optArgProto);
			if (si == null) {
				System.err.println(LocMsg.pr("e_unsupp_proto",
							     optArgProto)
						   );
				System.exit(-1);
			}
			port = si.getDefaultPort();
		}
		if (optArgProxy != null) {
			pi = getProxyInitialiser(optArgProxy);
		}

		/* Set up chain of socket initialisers ... */
		if (si != null) {
			si.setChainedInitialiser(pi);
		} else {
			si = pi;
		}

		if (optArgListFile != null) {
			hosts = FileHostIterator.getInstance(optArgListFile,
							     port);
		} else {
			/* Handle the non-option arguments:
			 * hostname and optional port number
			 */
			hosts = getHostsFromCmdLine(args, nextopt, port);

			/* if no file list given and no hostnames print
			 * usage
			 */
			if ((hosts == null) || (!hosts.hasNext())) {
				usage();
			}
		}
		if (hosts == null) {
			usage();
		}

		SSLFingerprint a = null;
		Publisher pub = null;
		if (optCheckOnly) {
			a = new SSLProbe();
			if (optXML) {
				pub = new XMLProbePublisher(xw, optVerbLevel);
			} else {
				pub = new CSVProbePublisher(log, optVerbLevel);
			}
		} else {
			a = new SSLFingerprint();
			if (optXML) {
				pub = new XMLFingerprintPublisher(xw, sc,
						              optVerbLevel);
			} else {
				String siName = null;
				if (si != null) {
					siName = si.getName();
				}
				pub = new PlainFingerprintPublisher(log, sc,
						              optVerbLevel,
						              siName);
			}
		}

		a.setSocketInitialiser(si);
		a.setCertValidator(cv);
		a.setDelay(delay);
		a.setAllSupported(optAllSupported);
		a.setAllowKerberos(optKerb);

		pub.setUseModHash(optModHash);
		pub.setCertValidator(cv);
		//pub.setClassifier(sc);

		pub.publishHeader();

		for ( /* */ ; hosts.hasNext(); /* next() called in loop */ ) {

			Host h = hosts.next();
			a.setTarget(h.name, h.port);
			SSLResult sr;

			try {
				sr = a.fingerprint();
				pub.publish(sr);
			} catch (IOException e) {
				if (!optXML) {
					log.log(Log.VERBOSE,
						e.toString());
				} else {
					System.err.println(e.toString());
				}
			}
		}

		pub.publishFooter();
		if (log != null) {
			log.close();
		}
		if (xw != null) {
			xw.close();
		}
	}

}
