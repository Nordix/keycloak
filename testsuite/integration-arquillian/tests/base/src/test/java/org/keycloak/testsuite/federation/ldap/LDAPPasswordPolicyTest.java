/*
 * Copyright 2020 Red Hat, Inc. and/or its affiliates
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
 *
 */

package org.keycloak.testsuite.federation.ldap;

import javax.ws.rs.core.Response;

import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.storage.StorageId;
import org.keycloak.testsuite.AbstractAuthTest;
import org.keycloak.testsuite.admin.ApiUtil;
import org.keycloak.testsuite.util.LDAPRule;

public class LDAPPasswordPolicyTest extends AbstractLDAPTest {

    @ClassRule
    public static LDAPRule ldapRule = new LDAPRule();


    @Override
    protected void afterImportTestRealm() {
    }

    @Override
    protected LDAPRule getLDAPRule() {
        return ldapRule;
    }


    @Test
    public void testCreateUser() {

        UserRepresentation user = AbstractAuthTest.createUserRepresentation("joe", "123");
        Response resp = testRealm().users().create(user);
        String userId = ApiUtil.getCreatedId(resp);
        resp.close();

        testRealm().users().get(userId).toRepresentation();
        Assert.assertTrue(StorageId.isLocalStorage(userId));
        Assert.assertNull(user.getFederationLink());

    }

}
