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
