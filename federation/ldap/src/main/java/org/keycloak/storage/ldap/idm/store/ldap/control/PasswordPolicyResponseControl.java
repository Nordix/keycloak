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

package org.keycloak.storage.ldap.idm.store.ldap.control;

import java.math.BigInteger;

import javax.naming.ldap.Control;

import org.jboss.logging.Logger;
import org.wildfly.security.asn1.ASN1;
import org.wildfly.security.asn1.ASN1Exception;
import org.wildfly.security.asn1.DERDecoder;

public class PasswordPolicyResponseControl implements Control {

    public static final String OID = "1.3.6.1.4.1.42.2.27.8.5.1";

    private static final Logger logger = Logger.getLogger(PasswordPolicyResponseControl.class);

    private static final int ERROR_CHANGE_AFTER_RESET = 2;

    private boolean changeAfterReset;

    /*
     * https://datatracker.ietf.org/doc/html/draft-behera-ldap-password-policy-11#section-6.2
     *
     * PasswordPolicyResponseValue ::= SEQUENCE {
     *    warning [0] CHOICE {
     *       timeBeforeExpiration [0] INTEGER (0 .. maxInt),
     *       graceAuthNsRemaining [1] INTEGER (0 .. maxInt) } OPTIONAL,
     *    error   [1] ENUMERATED {
     *       passwordExpired             (0),
     *       accountLocked               (1),
     *       changeAfterReset            (2),
     *       passwordModNotAllowed       (3),
     *       mustSupplyOldPassword       (4),
     *       insufficientPasswordQuality (5),
     *       passwordTooShort            (6),
     *       passwordTooYoung            (7),
     *       passwordInHistory           (8),
     *       passwordTooLong             (9) } OPTIONAL }
     */

    PasswordPolicyResponseControl(byte[] encodedValue) {
        DERDecoder der = new DERDecoder(encodedValue);

        try {
            der.startSequence(); // PasswordPolicyResponseValue ::= SEQUENCE
            if (der.isNextType(ASN1.CONTEXT_SPECIFIC_MASK, 0, false)) { // warning [0] CHOICE
                der.skipElement();
            }
            if (der.isNextType(ASN1.CONTEXT_SPECIFIC_MASK, 1, false)) { // error   [1] ENUMERATED
                der.decodeImplicit(1);
                this.changeAfterReset = new BigInteger(der.drainElementValue()).intValue() == ERROR_CHANGE_AFTER_RESET;
            }
            der.endSequence();
        } catch (ASN1Exception ignored) {
            logger.errorf("Failed to parse PasswordPolicyResponseControl value: %s", ignored.getMessage());
        }
    }

    public boolean changeAfterReset() {
        return changeAfterReset;
    }

    @Override
    public String getID() {
        return OID;
    }

    @Override
    public boolean isCritical() {
        return Control.NONCRITICAL;
    }

    @Override
    public byte[] getEncodedValue() {
        return new byte[0];
    }

}
