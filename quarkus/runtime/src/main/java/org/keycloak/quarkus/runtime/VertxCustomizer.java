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
package org.keycloak.quarkus.runtime;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.quarkus.runtime.integration.QuarkusKeycloakSessionFactory;
import org.keycloak.keystore.KeyStoreProvider;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;

import javax.enterprise.context.ApplicationScoped;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyStoreBuilderParameters;
import javax.net.ssl.X509KeyManager;

import io.quarkus.vertx.http.HttpServerOptionsCustomizer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.net.KeyCertOptions;

@ApplicationScoped
public class VertxCustomizer implements HttpServerOptionsCustomizer {

    private static final Logger log = Logger.getLogger(VertxCustomizer.class);

    @Override
    public void customizeHttpsServer(HttpServerOptions options) {
        try {
            QuarkusKeycloakSessionFactory instance = QuarkusKeycloakSessionFactory.getInstance();
            KeycloakSession session = instance.create();

            KeyStore.Builder ksb = session.getProvider(KeyStoreProvider.class)
                    .loadKeyStoreBuilder(KeyStoreProvider.HTTPS_SERVER_KEYSTORE);
            if (ksb != null) {
                log.info("Setting KeyStore to Vert.x");
                KeyManagerFactory kmf = KeyManagerFactory.getInstance("NewSunX509");
                kmf.init(new KeyStoreBuilderParameters(ksb));
                KeyCertOptions kco = KeyCertOptions.wrap((X509KeyManager) kmf.getKeyManagers()[0]);
                options.setKeyCertOptions(kco);
            }
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            log.error("Failed to set KeyManager: " + e.toString());
            throw new RuntimeException("Failed to set KeyManager: " + e.toString());
        }

    }
}
