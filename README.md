SSLFP README
===

sslfp is an SSL/TLS fingerprinting tool. While there are several such
tools and even online services, this tool is
<ul>
  <li>multi-platform as it's written in Java,</li>
  <li>fast making only the minimal possible number of requests,</li>
  <li>works behind proxy servers even with basic authentication,</li>
  <li>supports StartTLS for SMTP, POP3, IMAP.</li>
</ul>


Background
---

sslfp works by making connections to the server with a set of
ciphersuites offered. If the connection is established, the chosen
ciphersuite is supported and in turn excluded from future requests. If
the connection cannot be established due to not having a common
ciphersuite for client (sslfp) and server, all remaining ciphersuites
are known to be not supported by the server.

Classification of protocols and ciphersuites as secure or insecure is
based on the following criteria:
<ol>
  <li>SSL version 2 is broken, thus insecure, later protocols,
  i.e. SSL v3, TLS 1.0 and later, are assumed as secure.</li>

<li>Ciphersuites not authenticating the server ("anon") are
  insecure.</li>

<li>Ciphersuites with less than 128 bit keylength are
  insecure.</li>

<li>Ciphersuites with CBC mode are marked as
  problematic for protocols prior to TLS 1.1 due to the BEAST
  attack.</li>

<li>Ciphersuites with RC4 are marked as problematic due
  to recent cryptanalytic results by Bernstein et al.</li>

<li>Ciphersuites using RC2 are insecure.</li>

<li>Ciphersuites
  employing "null" ciphers or "null" message authentication codes are
  insecure.</li>

</ol>



Compilation
---

Type "ant".


Normal usage
---

To analyse a single ssl-enabled server run

	java -jar sslfp.jar server[:port]

or, for verbose output, run

	java -jar sslfp.jar -v server[:port]

You may want the output formatted in XML, then use 

	java -jar sslfp.jar -v server[:port]




Options
---

<table>
<tr>
  <td width="10%">-c</td>
       <td>Check only if SSL is supported at all, output as CSV.</td>
</tr>
<tr>
  <td>-x</td><td>Output as XML.</td>
</tr>
<tr>
  <td>-v</td>
        <td>Print verbose output. Repeat for even more verbose output.</td>
</tr>
<tr>
  <td>-d <i>n</i>
        </td><td>Wait for <i>n</i> milliseconds between requests.</td>
</tr>
<tr>
  <td>-m</td>
        <td>Compute hash of modulus (instead of all key data), compatible
            to debians openssl-vulnkey database (use right half of hash).</td>
</tr>
<tr>
  <td>-a</td>
        <td>Enable all supported ciphersuites for fingerprinting, instead
           of using only the ciphersuites enabled by default (except
           Kerberos ciphersuites which are controlled by the -k option).</td>
</tr>
<tr>
  <td>-k</td><td>Do <em>NOT</em> disable Kerberos ciphersuites.</td>
</tr>
<tr>
  <td>-f <i>file</i>
           </td><td>Read names of host[:port] from <i>file</i>
             instead of taking it from the command line. Use - for stdin.</td>
</tr>
<tr>
  <td>-V, -h, -?</td><td>Print version, help and exit.</td>
</tr>
<tr>
  <td>-p <i>proto</i></td>
           <td>Handle protocol proto where <i>proto</i> is one of
                       plain, smtp, imap, pop3
             (for plain ssl, starttls in smtp and imap, stls in pop3).</td>
</tr>
<tr>
  <td>-P <i>p-spec</i></td>
            <td>Use proxy given in <i>p-spec</i> as HTTP proxy, where
                  proxy-spec can be either in format
                        proxy[:port[:uid[:pw]]] or
                        [uid[:pw]]@proxy[:port].</td>
</tr>
</table>



Credits
---

sslfp is developed by Ulrich Kuehn (ukuehn AT acm.org) and is released under
the GPL v2 or later.

