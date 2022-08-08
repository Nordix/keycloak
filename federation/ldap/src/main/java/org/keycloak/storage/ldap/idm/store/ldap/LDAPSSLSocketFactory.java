/*
 * Copyright 2022 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.storage.ldap.idm.store.ldap;

import org.jboss.logging.Logger;
import org.keycloak.keystore.KeyStoreProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.truststore.TruststoreProvider;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Comparator;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyStoreBuilderParameters;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;


public class LDAPSSLSocketFactory extends SSLSocketFactory implements Comparator {

    private static final Logger log = Logger.getLogger(LDAPSSLSocketFactory.class);

    private static final AtomicReference<SSLSocketFactory> instance = new AtomicReference<>();

    private LDAPSSLSocketFactory() {
    }

    public static void initialize(KeycloakSession session) {
        try {
            // Initialize TrustManager with TrustStore provided by TrustStore SPI.
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            TruststoreProvider tsp = session.getProvider(TruststoreProvider.class);
            tmf.init(tsp.getTruststore());
            TrustManager[] tms = tmf.getTrustManagers();

            // Initialize KeyManager with KeyStore provided by KeyStore SPI.
            KeyManager[] kms = null;
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            KeyStore.Builder ksb = session.getProvider(KeyStoreProvider.class)
                    .loadKeyStoreBuilder(KeyStoreProvider.LDAP_CLIENT_KEYSTORE);
            if (ksb != null) {
                kmf.init(new KeyStoreBuilderParameters(ksb));
                kms = kmf.getKeyManagers();
            }

            log.infov("Initializing LDAP socket factory: trustStore={}, keyStore={}",
                    tms != null ? "yes" : "no",
                    kms != null ? "yes" : "no");

            SSLContext context = SSLContext.getInstance("TLS");
            context.init(kms, tms, null);

            instance.set(context.getSocketFactory());
        } catch (NoSuchAlgorithmException | KeyStoreException | InvalidAlgorithmParameterException
                | KeyManagementException e) {
            log.error("Failed to initialize SSLContext for LDAP: " + e.toString());
            throw new RuntimeException("Failed to initialize SSLContext: " + e.toString());
        }
    }

    public static SSLSocketFactory getDefault() {
        return instance.get();
    }

    /**
     * Enables LDAP connection pooling for sockets from custom socket factory.
     * See https://docs.oracle.com/javase/8/docs/technotes/guides/jndi/jndi-ldap.html#pooling
     */
    @Override
    public int compare(Object socketFactory1, Object socketFactory2) {
        return socketFactory1.equals(socketFactory2) ? 0 : -1;
    }

    // Following methods are not used by the JNDI LDAP implementation and therefore do not need to be implemented.

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
            throws IOException {
        throw new UnsupportedOperationException("Not implemented by LDAPSocketFactory");
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
        throw new UnsupportedOperationException("Not implemented by LDAPSocketFactory");
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
            throws IOException, UnknownHostException {
        throw new UnsupportedOperationException("Not implemented by LDAPSocketFactory");
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        throw new UnsupportedOperationException("Not implemented by LDAPSocketFactory");
    }

    @Override
    public String[] getDefaultCipherSuites() {
        throw new UnsupportedOperationException("Not implemented by LDAPSocketFactory");
    }

    @Override
    public String[] getSupportedCipherSuites() {
        throw new UnsupportedOperationException("Not implemented by LDAPSocketFactory");

    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        throw new UnsupportedOperationException("Not implemented by LDAPSocketFactory");
    }

}
