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


import java.io.*;
import java.util.Stack;

import org.xml.sax.SAXException;


public class SimpleXMLWriter extends Writer {

	final static int MAX_INDENT = 20;
	final static String NEWLINE = "\n";

	Stack<String> state;
	Writer out;
	boolean pendingCloseTag;


	public SimpleXMLWriter(Writer outParam) {
		out = outParam;
		state = new Stack<String>();
		pendingCloseTag = false;
	}


	protected void closePendingTag() throws IOException {
		if (pendingCloseTag) {
			out.write('>');
		}
		pendingCloseTag = false;
	}


	protected void indent(int depth) throws IOException {
		closePendingTag();
		if (depth > MAX_INDENT) {
			depth = MAX_INDENT;
		}
		out.write(NEWLINE);
		for (int i = 0;  i < depth;  i++) {
			out.write("  ");
		}
	}


	public void flush() throws IOException {
		closePendingTag();
		out.flush();
	}


	public void close() throws IOException {
		flush();
		out.close();
	}


	public void write(char[] cbuf, int off, int len)
		throws IOException {

		for (int i = off;  i < cbuf.length;  i++) {
			char c = cbuf[i];
			switch (c) {
			case '"':
				out.write("&quot;");
				break;
			case '\'':
				out.write("&apos;");
				break;
			case '&':
				out.write("&amp;");
				break;
			case '<':
				out.write("&lt;");
				break;
			case '>':
				out.write("&gt;");
				break;
			default:
				out.write(c);
				break;
			}
		}
	}


	public void startDocument() throws IOException {
		out.write("<?xml version=\"1.0\" standalone=\"yes\"?>");
	}


	public void startElement(String tagName)
		throws IOException, SAXException {
		closePendingTag();
		if (XML.needsEncoding(tagName)) {
			throw new SAXException(
				      "Forbidden character in tag name");
		}
		indent(state.size());
		state.push(tagName);
		out.write('<');
		out.write(tagName);
		pendingCloseTag = true;
	}


	public void attribute(String name, String value) 
		throws IOException, SAXException {
		if (!pendingCloseTag) {
			throw new SAXException(
			            "Attributes can only directy follow a tag"
				    );
		}
		if (XML.needsEncoding(name)) {
			throw new SAXException(
				    "Forbidden character in attribute name"
				    );
		}
		out.write(" ");
		out.write(name);
		out.write("="+XML.quote(value));
	}


	public void endElement()
		throws IOException, SAXException {
		if (state.empty()) {
			// Better throw an exception here, as this
			// points to an implementation error.
			// For know, do nothing and leave the output
			// document as valid xml.
			throw new SAXException(
				       "Closing tag without opening it.");
		}
		
		String tagName = state.pop();
		int depth = state.size();
		if (pendingCloseTag) {
			// This element does not contain
			// other elements, so make an inline close
			out.write(" />");
			pendingCloseTag = false;
		} else {
			indent(depth);
			out.write("</"+tagName+">");
		}
	}


	public void endDocument() throws IOException, SAXException {
		while (state.size() > 0) {
			endElement();
		}
		out.flush();
	}


	public void endDocumentNL() throws IOException, SAXException {
		while (state.size() > 0) {
			endElement();
		}
		out.write("\n");
		flush();
	}


	public void writeCharacters(String str) throws IOException {
		closePendingTag();
		out.write(XML.encode(str));
	}



	public static void main(String[] args)
		throws IOException, SAXException {

		PrintWriter out = new PrintWriter(System.out);
		SimpleXMLWriter xw = new SimpleXMLWriter(out);

		xw.startDocument();
		xw.startElement("Eins");
		xw.attribute("a-eins", "<>\"'&");
		xw.startElement("Zwei");
		xw.endElement();
		xw.endElement();
		xw.endDocument();
		xw.write("\n");
		xw.flush();
	}
	
}
