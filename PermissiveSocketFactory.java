package org.cts.restApi;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.http.HttpHost;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.HttpContext;

public class PermissiveSocketFactory extends SSLSocketFactory {
	SSLContext sslContext = SSLContext.getInstance(TLS);

	@SuppressWarnings("deprecation")
	public PermissiveSocketFactory(KeyStore truststore)
			throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, UnrecoverableKeyException {
		super(truststore);

		TrustManager tm = new X509TrustManager(){

			public X509Certificate[] getAcceptedIssuers() {
				return null;
			}

			public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			}

			public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {

			}
		};
		
		sslContext.init(null, new TrustManager[]{tm},null);
	}

	public PermissiveSocketFactory(String algorithm, KeyStore keystore, String keyPassword, KeyStore truststore,
			SecureRandom random, TrustStrategy trustStrategy, X509HostnameVerifier hostnameVerifier)
			throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, UnrecoverableKeyException {
		super(algorithm, keystore, keyPassword, truststore, random, trustStrategy, hostnameVerifier);
		TrustManager tm = new X509TrustManager() {

			public X509Certificate[] getAcceptedIssuers() {
				return null;
			}

			public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			}

			public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {

			}
		};
		
		KeyManagerFactory km = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		km.init(keystore, keyPassword!=null ? keyPassword.toCharArray() :null);
		
		sslContext.init(km.getKeyManagers(), new TrustManager[]{tm}, null);
	}

	


	@Override
	public Socket createSocket(Socket socket, String host, int port, boolean autoClose)
			throws IOException, UnknownHostException {
		// TODO Auto-generated method stub
		return sslContext.getSocketFactory().createSocket(socket, host, port, autoClose);
	}

	@Override
	public Socket createSocket() throws IOException {
		// TODO Auto-generated method stub
		return sslContext.getSocketFactory().createSocket();
	}

	
	@Override
	public Socket createSocket(HttpParams context) throws IOException {
		SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket();
		this.prepareSocket(socket);
		return socket;
	}

	
	@Override
	public boolean isSecure(Socket socket) throws IllegalArgumentException {
		// TODO Auto-generated method stub
		return true;
	}
	
	
	
}
