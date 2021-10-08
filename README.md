package com.polarion.platform.security.auth.impl;

import com.polarion.core.util.EscapeChars;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Writer;
import java.net.URLEncoder;
import java.util.Base64.Decoder;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.Base64;
import java.util.Iterator;
import java.util.Map;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public final class HttpUtils {
	@NotNull
	public static final String FORM_SCRIPT = "var form = document.getElementById('loginForm'); form.action += window.location.hash; form.submit();";
	@NotNull
	private static final String FORM_SAML_SCRIPT_HASH_REDIRECT = " \n// <![CDATA[ \n    var loc = window.location.pathname + window.location.search + window.location.hash;    var hash = window.location.hash;    if (loc != null && loc.indexOf('/polarion/#/') != -1 && hash != null && hash.length != 0) {        loc = loc.replace(hash, 'redirect' + hash.substring(1));        window.location.replace(loc);    } else {    var form = document.getElementById('loginForm'); form.action += window.location.hash; form.submit(); } \n// ]]> \n";
	@NotNull
	public static final String FORM_SAML_SCRIPT_HASH_REDIRECT_WITHOUT_CDATA = " \n// <![CDATA[ \n    var loc = window.location.pathname + window.location.search + window.location.hash;    var hash = window.location.hash;    if (loc != null && loc.indexOf('/polarion/#/') != -1 && hash != null && hash.length != 0) {        loc = loc.replace(hash, 'redirect' + hash.substring(1));        window.location.replace(loc);    } else {    var form = document.getElementById('loginForm'); form.action += window.location.hash; form.submit(); } \n// ]]> \n"
			.replace("<![CDATA[", "").replace("]]>", "");
	@NotNull
	private static final String FORM_SCRIPT_WITH_TAGS = String.format(
			"</form><script type='text/javascript'>%s</script></body></html>",
			"var form = document.getElementById('loginForm'); form.action += window.location.hash; form.submit();");
	@NotNull
	private static final String FORM_SAML_SCRIPT_HASH_REDIRECT_WITH_TAGS = String.format(
			"</form><script type='text/javascript'>%s</script></body></html>",
			" \n// <![CDATA[ \n    var loc = window.location.pathname + window.location.search + window.location.hash;    var hash = window.location.hash;    if (true) {        loc = loc.replace(hash, 'redirect' + hash.substring(1));        window.location.replace(loc);    } else {    var form = document.getElementById('loginForm'); form.action += window.location.hash; form.submit(); } \n// ]]> \n");
//	private static final String FORM_SAML_SCRIPT_HASH_REDIRECT_WITH_TAGS = String.format(
//			"</form><script type='text/javascript'>%s</script></body></html>",
//			" \n// <![CDATA[ \n    var loc = window.location.pathname + window.location.search + window.location.hash;    var hash = window.location.hash;    if (loc != null && loc.indexOf('/polarion/#/') != -1 && hash != null && hash.length != 0) {        loc = loc.replace(hash, 'redirect' + hash.substring(1));        window.location.replace(loc);    } else {    var form = document.getElementById('loginForm'); form.action += window.location.hash; form.submit(); } \n// ]]> \n");
	@NotNull
	
	private static final String SESSION_COOKIE_NAME = "JSESSIONID";
	@NotNull
	private final HttpServletRequest request;
	@NotNull
	private final HttpServletResponse response;

	public HttpUtils(@NotNull HttpServletRequest request, @NotNull HttpServletResponse response) {
		this.request = request;
		this.response = response;
	}

	public void createForm(@NotNull String url, @NotNull Map<String, String> values, @NotNull String method)
			throws IOException {
		this.response.setContentType("text/html; charset=UTF-8");
		this.response.addHeader("Cache-Control", "no-store");

		this.response.addHeader("X-com-ibm-team-repository-web-auth-msg", "authrequired");
		Writer writer = this.response.getWriter();
		String actionUrl = this.response.encodeURL(url);

		this.handleNewSessions();

		writer.write(String.format("<html><head></head><body><form id='loginForm' action='%s' method='%s'>",
				EscapeChars.forHTMLTag(actionUrl), method));
		Iterator var7 = values.keySet().iterator();
		StringBuilder queryBuilder = new StringBuilder("");
		while (var7.hasNext()) {
			String key = (String) var7.next();
			String encodedKey = EscapeChars.forHTMLTag(key);
			String encodedValue = EscapeChars.forHTMLTag((String) values.get(key));
			writer.write(String.format("<input type='hidden' id='%s' name='%s' value='%s'/>", encodedKey, encodedKey,
					encodedValue));
			if (queryBuilder.toString().isEmpty()) {
				queryBuilder.append("?");
				String tempStr = new String(Base64.getDecoder().decode(encodedValue.getBytes()));
				encodedValue = makeSamlForGetMethod(tempStr);
//				System.out.println("--->" +encodedValue);
			} else {
				queryBuilder.append("&");
			}
			
			queryBuilder.append(encodedKey).append("=");
			queryBuilder.append(encodedValue);
		}
		if (true) {
			String urlCheck = actionUrl + queryBuilder.toString();
			System.out.println("--->" +urlCheck);
			response.sendRedirect(urlCheck);
			
		} else {
			if ((!values.containsKey("SAMLRequest") || !values.containsKey("RelayState"))
					&& (!values.containsKey("redirect_uri") || !values.containsKey("client_id"))) {
				writer.write(FORM_SCRIPT_WITH_TAGS);
			} else {
				writer.write(FORM_SAML_SCRIPT_HASH_REDIRECT_WITH_TAGS);
			}

			writer.flush();
		}

	}

	public void postForm(@NotNull String url, @NotNull Map<String, String> values) throws IOException {
//		this.createForm(url, values, "POST");
		this.createForm(url, values, "GET");
		
	}

	public void getForm(@NotNull String url, @NotNull Map<String, String> values) throws IOException {
		this.createForm(url, values, "GET");
	}

	private void handleNewSessions() {
		HttpSession session = this.request.getSession(false);
		Cookie[] cookies = this.request.getCookies();
		boolean sessionCookieFound = false;
		if (cookies != null) {
			Cookie[] var7 = cookies;
			int var6 = cookies.length;
			for (int var5 = 0; var5 < var6; ++var5) {
				Cookie cookie = var7[var5];
				if ("JSESSIONID".equals(cookie.getName())) {
					sessionCookieFound = true;
				}
			}
		}

		if (session != null && !sessionCookieFound) {
			this.response.addCookie(new Cookie("JSESSIONID", session.getId()));
		}
	}

	@Nullable
	public static String cleanupAndGetQueryString(@NotNull HttpServletRequest param0) {
		return "";
	}

	@NotNull
	public static String getSsoRequestUri(@NotNull String param0) {
		return "";
	}
	
	private static String  makeSamlForGetMethod(String samlRequestXml) throws IOException {
		byte[] byteArr = samlRequestXml.getBytes();
		
		ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
		Deflater deflater = new Deflater(Deflater.DEFLATED, true);
		DeflaterOutputStream deflaterStream = new DeflaterOutputStream(bytesOut, deflater);
		deflaterStream.write(byteArr);
		deflaterStream.finish();
		String base64EncodedStr = new String(Base64.getEncoder().encode(bytesOut.toByteArray()));
		String urlEncoded = URLEncoder.encode(base64EncodedStr);
		return urlEncoded;
	}
}
