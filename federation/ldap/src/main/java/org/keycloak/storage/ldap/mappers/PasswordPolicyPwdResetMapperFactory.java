package org.keycloak.storage.ldap.mappers;

import org.keycloak.component.ComponentModel;
import org.keycloak.storage.ldap.LDAPStorageProvider;

public class PasswordPolicyPwdResetMapperFactory extends AbstractLDAPStorageMapperFactory {

    public static final String PROVIDER_ID = "password-policy-pwdreset-mapper";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    protected AbstractLDAPStorageMapper createMapper(ComponentModel mapperModel,
            LDAPStorageProvider federationProvider) {
        return new PasswordPolicyPwdResetMapper(mapperModel, federationProvider);
    }

}
