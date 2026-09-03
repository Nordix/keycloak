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
package org.keycloak.services.managers;

import org.keycloak.exceptions.TokenVerificationException;
import org.keycloak.representations.JsonWebToken;

/**
 * Exception thrown when the token is valid, but the client it was issued for no longer exists.
 */
public class TokenClientNotFoundException extends TokenVerificationException {

    public TokenClientNotFoundException(JsonWebToken token, String message) {
        super(token, message);
    }

}
