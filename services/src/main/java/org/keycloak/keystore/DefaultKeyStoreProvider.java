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

package org.keycloak.keystore;

import java.io.IOException;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStore.Builder;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;

import org.jboss.logging.Logger;
import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class DefaultKeyStoreProvider implements KeyStoreProvider, KeyStoreProviderFactory {

    private static final Logger log = Logger.getLogger(DefaultKeyStoreProvider.class);

    private KeyStore.Builder ldapKeyStoreBuilder;

    @Override
    public void close() {
        // Nothing to do here.
    }

    /**
     * Returns named keystore.
     *
     * @param keyStoreIdentifier The identifier of requested keystore.
     * @return Reference to a keystore.
     * @throws KeyStoreException
     */
    @Override
    public KeyStore loadKeyStore(String keyStoreIdentifier) {
        try {
            return loadKeyStoreBuilder(keyStoreIdentifier).getKeyStore();
        } catch (KeyStoreException e) {
            log.errorv("Cannot load KeyStore {0}", keyStoreIdentifier);
            throw new RuntimeException("Cannot load KeyStore " + keyStoreIdentifier + ":" + e.getMessage());
        }
    }

    @Override
    public Builder loadKeyStoreBuilder(String keyStoreIdentifier) {
        if (keyStoreIdentifier.equals(LDAP_CLIENT_KEYSTORE)) {
            return ldapKeyStoreBuilder;
        }

        log.errorv("loadKeyStoreBuilder was called with invalid keystore identifier {0}", keyStoreIdentifier);
        throw new IllegalArgumentException("invalid keystore requested, keyStoreIdentifier:" + keyStoreIdentifier);
    }

    @Override
    public KeyStoreProvider create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Scope config) {
        // Allow changing the default duration that defines how frequently at most the backing file(s) will be checked
        // for modification. The value is parsed as ISO8601 time duration (e.g. "1s", "2m30s", "1h").
        String cacheTtl = config.get("keyStoreCacheTtl");
        if (cacheTtl != null) {
            log.infov("Setting reloading keyStore cache TTL to {0}", cacheTtl);
            ReloadingKeyStore.setDefaultKeyStoreCacheTtl(Duration.parse("PT" + cacheTtl));
        }

        // Check if LDAP credentials are given as PEM files.
        String ldapCertificateFile = config.get("ldapCertificateFile");
        String ldapCertificateKeyFile = config.get("ldapCertificateKeyFile");
        if (ldapCertificateFile != null && ldapCertificateKeyFile != null) {
            log.infov("Loading client credentials for LDAP federation: {0}, {1}", ldapCertificateFile,
                    ldapCertificateKeyFile);
            try {
                ldapKeyStoreBuilder = ReloadingKeyStore.Builder.fromPem(Paths.get(ldapCertificateFile),
                        Paths.get(ldapCertificateKeyFile));
            } catch (NoSuchAlgorithmException | CertificateException | IllegalArgumentException | KeyStoreException
                    | InvalidKeySpecException | IOException e) {
                throw new RuntimeException("Failed to initialize keystore: " + e.toString());
            }
        }

        // Check if LDAP credentials are given as KeyStore file.
        String ldapKeyStoreFile = config.get("ldapKeystoreFile");
        String ldapKeyStorePassword = config.get("ldapKeystorePassword");
        String ldapKeyStoreType = config.get("ldapKeystoreType", "JKS");

        // Check if both PEM files and KeyStore is configured.
        if (ldapKeyStoreBuilder != null && ldapKeyStoreFile != null) {
            log.warn("Both PEM files and KeyStore was configured for LDAP federation");
            throw new IllegalArgumentException("Both PEM files and KeyStore was configured for LDAP federation. Choose only one.");
        }

        // Check if keyStore file is configured without password.
        if (ldapKeyStoreFile != null && ldapKeyStorePassword == null) {
            log.errorv("Password not given for LDAP client keystore {0}", ldapKeyStoreFile);
            throw new IllegalArgumentException("Password not given for LDAP client keystore: " + ldapKeyStoreFile);
        }

        if (ldapKeyStoreFile != null) {
            try {
                log.infov("Loading client credentials for LDAP federation: {0}", ldapKeyStoreFile);
                ldapKeyStoreBuilder = ReloadingKeyStore.Builder
                        .fromKeyStoreFile(ldapKeyStoreType, Paths.get(ldapKeyStoreFile), ldapKeyStorePassword);
            } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
                throw new RuntimeException("Failed to initialize keystore: " + e.toString());
            }
        }
    }

    @Override
    public String getId() {
        return "default";
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Nothing to do here.
    }



}
