package org.cts.restApi;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.*;

import org.apache.http.conn.ssl.SSLSocketFactory;

import com.jayway.restassured.RestAssured;
import com.jayway.restassured.authentication.CertificateAuthSettings;
import com.jayway.restassured.response.Header;
import com.jayway.restassured.specification.RequestSpecification;

@SuppressWarnings("deprecation")
public class CreateRequest {
	
	String authDetails = "<true or false>";
	String authType = "<type of authentication - BASIC/PKCS/SPID>";
	String trustStoreType= "<truststoretype>";
	String trusStorePath="<truststore file path>";
	String trustStorePassword ="<trust store file password>";
	String KeyStorePath="<truststore file path>";
	String KeyStorePassword ="<trust store file password>";
	String basic_USE_RELAXED="<true or false>";
	String serverUser = "<server username>";
	String serverPassword = "<server password>";
	
	
	@SuppressWarnings("unused")
	private RequestSpecification getReqSpecification() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		
		RequestSpecification request = null;
		
		if (authDetails.equalsIgnoreCase("true") && authType.equalsIgnoreCase("PKCS") )
		{
				System.out.println("Authenticatinng with .pkcs/p12");
			FileInputStream fis = new FileInputStream(new File(trusStorePath));
			
			KeyStore ks = KeyStore.getInstance(trustStoreType);
			ks.load(fis, trustStorePassword.toCharArray());
			
			fis.close();
			
			try {
				PermissiveSocketFactory mySSLsocketFactory = new PermissiveSocketFactory("SSLv3", ks, trustStorePassword, null, new SecureRandom(), null, SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
				
				CertificateAuthSettings certAuthSettings = new CertificateAuthSettings().keystoreType(trustStoreType).sslSocketFactory(mySSLsocketFactory);
				
				request = RestAssured.given().auth().certificate(trusStorePath, trustStorePassword, certAuthSettings);
				
				Header authenticateHeader = getHeaderAuthentication();
				
				if(authenticateHeader !=null)
					request.header(authenticateHeader);
				
			} catch (Exception e) {
				e.printStackTrace();} 
		}
		else if(authDetails.equalsIgnoreCase("true") && authType.equals("BASIC"))
		{
			Header authenticateHeader = getHeaderAuthentication();
			if(basic_USE_RELAXED.equals("true"))
			{request = RestAssured.given().header(authenticateHeader).relaxedHTTPSValidation();}
			else
			{request = RestAssured.given().header(authenticateHeader);}
			
		}
		else if (authDetails.equalsIgnoreCase("true") && authType.equals("SPID"))
		{
			System.out.println("Authenticatinng with .jks");
			FileInputStream fis = new FileInputStream(new File(trusStorePath));
			
			KeyStore ks = KeyStore.getInstance(trustStoreType);
			ks.load(fis, trustStorePassword.toCharArray());
			
			fis.close();
			
			CertificateAuthSettings certAuthSettings = new CertificateAuthSettings().trustStore(ks).allowAllHostnames();
			
			request = RestAssured.given().auth().certificate(KeyStorePath, KeyStorePassword, certAuthSettings);
		
		}
		else
			{ request = RestAssured.given();}
		return request;
		
		} 
		private Header getHeaderAuthentication() {
			String basicServerUser = null;
			String basicServerPass = null;
			
			if(serverUser !=null && serverPassword !=null)
			{
				basicServerUser = serverUser;
				basicServerPass = serverPassword;
			}
			if(basicServerPass !=null && basicServerUser !=null)
			{
				Header header = new Header("Authorization","Basic"+ (Base64.getEncoder().encode((basicServerUser+":"+basicServerPass).getBytes())));
				return header;
			}
			return null;	

		}
}
