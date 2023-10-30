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
import org.keycloak.storage.ldap.LDAPConfig;
import org.keycloak.truststore.TruststoreProvider;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509CertSelector;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;

import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyStoreBuilderParameters;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;


public class LDAPSSLSocketFactory extends SSLSocketFactory implements Comparator<String> {

    private static final String NOT_IMPLEMENTED_BY_LDAP_SOCKET_FACTORY = "Not implemented by LDAPSSLSocketFactory";

    private static final Logger log = Logger.getLogger(LDAPSSLSocketFactory.class);

    private static SSLSocketFactory instance = null;

    private LDAPSSLSocketFactory() {
    }

    public static synchronized void initialize(KeycloakSession session, LDAPConfig config) {
        if (instance == null) {
            try {
                // Initialize TrustManager with TrustStore provided by TrustStore SPI.
                TruststoreProvider tsp = session.getProvider(TruststoreProvider.class);
                if (tsp == null) {
                    new RuntimeException("Truststore SPI used but Truststore was not configured");
                }
                KeyStore trustStore = tsp.getTruststore();

                PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(trustStore, new X509CertSelector());
                String crlFile = config.getCrlUri();
                if (crlFile != null) {
                    log.infov("Initializing LDAPSSLSocketFactory with CRL: {0}", crlFile);
                    Collection<CRL> crls = new HashSet<>();
                    crls.add(CertificateFactory.getInstance("X.509").generateCRL(Files.newInputStream(Paths.get(crlFile))));

                    List<CertStore> certStores = new ArrayList<>();
                    certStores.add(CertStore.getInstance("Collection", new CollectionCertStoreParameters(crls)));

                    PKIXRevocationChecker revocationChecker = (PKIXRevocationChecker) CertPathBuilder.getInstance("PKIX").getRevocationChecker();
                    revocationChecker.setOptions(
                        EnumSet.of(PKIXRevocationChecker.Option.PREFER_CRLS, PKIXRevocationChecker.Option.NO_FALLBACK));

                    pkixParams.setCertStores(certStores);
                    pkixParams.addCertPathChecker(revocationChecker);
                }
                //pkixParams.setRevocationEnabled(false);
                TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(new CertPathTrustManagerParameters(pkixParams));

                TrustManager[] tms = tmf.getTrustManagers();

                // Initialize KeyManager with KeyStore provided by KeyStore SPI.
                KeyManager[] kms = null;
                KeyManagerFactory kmf = KeyManagerFactory.getInstance("NewSunX509");
                KeyStore.Builder ksb = session.getProvider(KeyStoreProvider.class)
                        .loadKeyStoreBuilder(KeyStoreProvider.LDAP_CLIENT_KEYSTORE);
                if (ksb != null) {
                    kmf.init(new KeyStoreBuilderParameters(ksb));
                    kms = kmf.getKeyManagers();
                }

                log.infov("Initializing LDAPSSLSocketFactory: trustStore={0}, keyStore={1}",
                        tms != null ? "yes" : "no",
                        kms != null ? "yes" : "no");

                SSLContext context = SSLContext.getInstance("TLS");
                context.init(kms, tms, null);

                instance = context.getSocketFactory();
            } catch (NoSuchAlgorithmException | KeyStoreException | KeyManagementException | InvalidAlgorithmParameterException | CRLException | CertificateException | IOException e) {
                log.error("Failed to initialize SSLContext for LDAP: " + e.toString());
                throw new RuntimeException("Failed to initialize SSLContext: " + e.toString());
            }
        }
    }

    public static SSLSocketFactory getDefault() {
        return instance;
    }

    /**
     * Enables LDAP connection pooling for sockets from custom socket factory.
     * See https://docs.oracle.com/javase/8/docs/technotes/guides/jndi/jndi-ldap.html#pooling
     *
     * Note that Comparator<String> needs to be implemented since JDK uses the class name as string for the comparison.
     *
     * For more information, see:
     * https://stackoverflow.com/questions/23898970/pooling-ldap-connections-with-custom-socket-factory
     * https://bugs.openjdk.org/browse/JDK-6587244?page=com.atlassian.jira.plugin.system.issuetabpanels%3Aworklog-tabpanel
     */
    @Override
    public int compare(String o1, String o2) {
        return o1.compareTo(o2);
    }

    // Following methods are not used by the JNDI LDAP implementation and therefore do not need to be implemented.

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        throw new UnsupportedOperationException(NOT_IMPLEMENTED_BY_LDAP_SOCKET_FACTORY);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
            throws IOException {
        throw new UnsupportedOperationException(NOT_IMPLEMENTED_BY_LDAP_SOCKET_FACTORY);
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        throw new UnsupportedOperationException(NOT_IMPLEMENTED_BY_LDAP_SOCKET_FACTORY);
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
            throws IOException {
        throw new UnsupportedOperationException(NOT_IMPLEMENTED_BY_LDAP_SOCKET_FACTORY);
    }

    @Override
    public String[] getDefaultCipherSuites() {
        throw new UnsupportedOperationException(NOT_IMPLEMENTED_BY_LDAP_SOCKET_FACTORY);
    }

    @Override
    public String[] getSupportedCipherSuites() {
        throw new UnsupportedOperationException(NOT_IMPLEMENTED_BY_LDAP_SOCKET_FACTORY);
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        throw new UnsupportedOperationException(NOT_IMPLEMENTED_BY_LDAP_SOCKET_FACTORY);
    }

}
