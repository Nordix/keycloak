/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.tests.admin;

import java.io.IOException;
import java.util.Base64;

import org.keycloak.common.util.Time;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpRequest;
import org.keycloak.http.simple.SimpleHttpResponse;
import org.keycloak.models.AdminRoles;
import org.keycloak.models.Constants;
import org.keycloak.testframework.annotations.InjectKeycloakUrls;
import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.annotations.InjectSimpleHttp;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.oauth.OAuthClient;
import org.keycloak.testframework.oauth.annotations.InjectOAuthClient;
import org.keycloak.testframework.realm.ManagedRealm;
import org.keycloak.testframework.realm.RealmBuilder;
import org.keycloak.testframework.realm.RealmConfig;
import org.keycloak.testframework.realm.UserBuilder;
import org.keycloak.testframework.remote.timeoffset.InjectTimeOffSet;
import org.keycloak.testframework.remote.timeoffset.TimeOffSet;
import org.keycloak.testframework.server.KeycloakUrls;

import org.junit.jupiter.api.Test;

import static jakarta.ws.rs.core.HttpHeaders.WWW_AUTHENTICATE;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

/**
 * WWW-Authenticate challenge returned by the admin REST API when bearer token authentication fails.
 *
 * Uses its own realm instead of master, as some of the tests change realm settings that would
 * otherwise invalidate the admin token the test framework uses for cleanup.
 */
@KeycloakIntegrationTest
public class AdminBearerChallengeTest {

    private static final String USERNAME = "realm-admin";
    private static final String PASSWORD = "password";

    private static final String UNAUTHORIZED_BODY = "{\"error\":\"HTTP 401 Unauthorized\"}";
    private static final String UNAUTHORIZED_BODY_PREFIX = "{\"error\":\"HTTP 401 Unauthorized\",\"error_description\":\"";

    @InjectKeycloakUrls
    KeycloakUrls keycloakUrls;

    @InjectSimpleHttp
    SimpleHttp simpleHttp;

    @InjectRealm(config = AdminAuthRealmConfig.class)
    ManagedRealm realm;

    @InjectOAuthClient
    OAuthClient oauth;

    @InjectTimeOffSet
    TimeOffSet timeOffSet;

    @Test
    public void noToken() throws IOException {
        try (SimpleHttpResponse response = adminGet(null)) {
            assertThat(response.getStatus(), is(401));
            assertThat(response.getFirstHeader(WWW_AUTHENTICATE), is("Bearer"));
            assertThat(response.asString(), is(UNAUTHORIZED_BODY));
        }
    }

    @Test
    public void garbageToken() throws IOException {
        try (SimpleHttpResponse response = adminGet("not-a-jwt")) {
            assertThat(response.getStatus(), is(401));
            assertThat(response.getFirstHeader(WWW_AUTHENTICATE),
                    is("Bearer error=\"invalid_token\", error_description=\"Token format is invalid\""));
            assertThat(response.asString(), is(unauthorizedBody("Token format is invalid")));
        }
    }

    @Test
    public void unknownRealm() throws IOException {
        // Realm lookup happens before signature verification, so a hand-crafted token is enough
        String token = base64Url("{\"alg\":\"RS256\",\"typ\":\"JWT\"}") + "."
                + base64Url("{\"iss\":\"" + keycloakUrls.getBase() + "/realms/nonexistent\"}") + ".AAAA";

        try (SimpleHttpResponse response = adminGet(token)) {
            assertThat(response.getStatus(), is(401));
            assertThat(response.getFirstHeader(WWW_AUTHENTICATE),
                    is("Bearer error=\"invalid_token\", error_description=\"Token verification failed\""));
            assertThat(response.asString(), is(unauthorizedBody("Token verification failed")));
        }
    }

    @Test
    public void invalidSignature() throws IOException {
        // Replace the signature with a wrong value
        String[] parts = accessToken().split("\\.");
        parts[2] = "A".repeat(parts[2].length());

        try (SimpleHttpResponse response = adminGet(String.join(".", parts))) {
            assertThat(response.getStatus(), is(401));
            assertThat(response.getFirstHeader(WWW_AUTHENTICATE), is(challenge("Token signature is invalid")));
            assertThat(response.asString(), is(unauthorizedBody("Token signature is invalid")));
        }
    }

    @Test
    public void expiredToken() throws IOException {
        String token = accessToken();
        timeOffSet.set(600);

        try (SimpleHttpResponse response = adminGet(token)) {
            assertThat(response.getStatus(), is(401));
            assertThat(response.getFirstHeader(WWW_AUTHENTICATE),
                    is(challenge("The access token is outside its validity period")));
            assertThat(response.asString(), is(unauthorizedBody("The access token is outside its validity period")));
        }
    }

    @Test
    public void realmNotBefore() throws IOException {
        String token = accessToken();
        realm.updateWithCleanup(r -> r.notBefore(Time.currentTime() + 60));

        try (SimpleHttpResponse response = adminGet(token)) {
            assertThat(response.getStatus(), is(401));
            assertThat(response.getFirstHeader(WWW_AUTHENTICATE),
                    is(challenge("The access token is outside its validity period")));
            assertThat(response.asString(), is(unauthorizedBody("The access token is outside its validity period")));
        }
    }

    @Test
    public void validToken() throws IOException {
        try (SimpleHttpResponse response = adminGet(accessToken())) {
            assertThat(response.getStatus(), is(200));
            assertThat(response.getFirstHeader(WWW_AUTHENTICATE), is(nullValue()));
        }
    }

    @Test
    public void nonBearerAuthScheme() throws IOException {
        String url = keycloakUrls.getAdmin() + "/realms/" + realm.getName() + "/clients?max=1";
        try (SimpleHttpResponse response = simpleHttp.doGet(url).header("Authorization", "Basic dXNlcjpwYXNz").asResponse()) {
            assertThat(response.getStatus(), is(401));
            assertThat(response.getFirstHeader(WWW_AUTHENTICATE), is("Bearer"));
            assertThat(response.asString(), is(UNAUTHORIZED_BODY));
        }
    }

    @Test
    public void emptyBearerToken() throws IOException {
        String url = keycloakUrls.getAdmin() + "/realms/" + realm.getName() + "/clients?max=1";
        try (SimpleHttpResponse response = simpleHttp.doGet(url).header("Authorization", "Bearer ").asResponse()) {
            assertThat(response.getStatus(), is(401));
            assertThat(response.getFirstHeader(WWW_AUTHENTICATE), is("Bearer"));
            assertThat(response.asString(), is(UNAUTHORIZED_BODY));
        }
    }

    @Test
    public void adminConsoleWhoamiNoToken() throws IOException {
        String url = keycloakUrls.getBase() + "/admin/" + realm.getName() + "/console/whoami";

        try (SimpleHttpResponse response = simpleHttp.doGet(url).asResponse()) {
            assertThat(response.getStatus(), is(401));
            assertThat(response.getFirstHeader(WWW_AUTHENTICATE), is("Bearer realm=\"" + realm.getName() + "\""));
            assertThat(response.asString(), is(UNAUTHORIZED_BODY));
        }
    }

    private String challenge(String errorDescription) {
        return "Bearer realm=\"" + realm.getName() + "\", error=\"invalid_token\""
                + ", error_description=\"" + errorDescription + "\"";
    }

    private static String unauthorizedBody(String errorDescription) {
        return UNAUTHORIZED_BODY_PREFIX + errorDescription + "\"}";
    }

    private String accessToken() {
        return oauth.doPasswordGrantRequest(USERNAME, PASSWORD).getAccessToken();
    }

    private SimpleHttpResponse adminGet(String token) throws IOException {
        String url = keycloakUrls.getAdmin() + "/realms/" + realm.getName() + "/clients?max=1";
        SimpleHttpRequest request = simpleHttp.doGet(url);
        return token != null ? request.auth(token).asResponse() : request.asResponse();
    }

    private static String base64Url(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes());
    }

    public static class AdminAuthRealmConfig implements RealmConfig {

        @Override
        public RealmBuilder configure(RealmBuilder realm) {
            return realm.users(UserBuilder.create()
                    .username(USERNAME)
                    .password(PASSWORD)
                    .name("Realm", "Admin")
                    .email("realm-admin@localhost")
                    .emailVerified(true)
                    .clientRoles(Constants.REALM_MANAGEMENT_CLIENT_ID, AdminRoles.REALM_ADMIN));
        }
    }
}
