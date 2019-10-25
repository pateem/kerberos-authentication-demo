package com.sap.learning;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Optional;

public class KerberosTest {

	private static final String KRB_SECURED_SERVICE_URL = "https://example.org/api/people";
	private static final String USERNAME = "user";
	private static final String PASSWORD = "pass";

	private static Subject subject;

	@BeforeClass
	public static void before() throws LoginException {
		subject = KerberosAuthentication.login(USERNAME, PASSWORD);

	}

	@Test
	public void testThatApiRespondWithOk_whenKerberosProtectedApiIsCalled() throws PrivilegedActionException {
		final PrivilegedExceptionAction<Integer> action = () -> {
			HttpURLConnection conn = (HttpURLConnection) new URL(KRB_SECURED_SERVICE_URL).openConnection();
			return conn.getResponseCode();
		};

		Integer responseCode = Subject.doAs(subject, action);
		Assert.assertEquals((Integer)200, responseCode);
	}

	@Test
	public void testThatSpnegoTokenIsReturned() throws MalformedURLException, PrivilegedActionException {
		URL url = new URL(KRB_SECURED_SERVICE_URL);
		Optional<String> token = Subject.doAs(subject, SpnegoAuthentication.getSpnegoToken(url.getHost()));
		Assert.assertTrue(token.isPresent());
	}

}
