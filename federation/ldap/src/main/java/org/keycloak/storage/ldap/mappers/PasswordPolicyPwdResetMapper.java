package org.keycloak.storage.ldap.mappers;

import java.util.stream.Stream;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.LDAPConstants;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.UserModelDelegate;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.idm.model.LDAPObject;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQuery;

public class PasswordPolicyPwdResetMapper extends AbstractLDAPStorageMapper {

    public PasswordPolicyPwdResetMapper(ComponentModel mapperModel, LDAPStorageProvider ldapProvider) {
        super(mapperModel, ldapProvider);
    }

    @Override
    public void onImportUserFromLDAP(LDAPObject ldapUser, UserModel user, RealmModel realm, boolean isCreate) {
    }

    @Override
    public void onRegisterUserToLDAP(LDAPObject ldapUser, UserModel localUser, RealmModel realm) {
    }

    @Override
    public UserModel proxy(LDAPObject ldapUser, UserModel delegate, RealmModel realm) {
        String pwdResetAsString = ldapUser.getAttributeAsString(LDAPConstants.PPOLICY_PWD_RESET);

        // Wrap the user delegate to force the user to update the password when
        // pwdReset==true.
        delegate = new UserModelDelegate(delegate) {

            private boolean pwdReset = pwdResetAsString != null && Boolean.parseBoolean(pwdResetAsString);

            @Override
            public Stream<String> getRequiredActionsStream() {
                if (pwdReset) {
                    // Return UPDATE_PASSWORD action to force the user to update the password.
                    return Stream.concat(super.getRequiredActionsStream(),
                            Stream.of(UserModel.RequiredAction.UPDATE_PASSWORD.name()));
                } else {
                    return super.getRequiredActionsStream();
                }
            }

            @Override
            public void removeRequiredAction(String action) {
                // Ignore the request to remove UPDATE_PASSWORD (we cannot remove pwdReset
                // attribute from the LDAP server), but since the password has now been updated,
                // we need to fetch the current state of the pwdReset attribute again.
                if (action.equals(UserModel.RequiredAction.UPDATE_PASSWORD.name())) {
                    pwdReset = fetchPwdResetFromLDAP();
                    return;
                }

                super.removeRequiredAction(action);
            }

            @Override
            public void removeRequiredAction(RequiredAction action) {
                // Ignore the request to remove UPDATE_PASSWORD (we cannot remove pwdReset
                // attribute from the LDAP server), but since the password has now been updated,
                // we need to fetch the current state of the pwdReset attribute again.
                if (action == RequiredAction.UPDATE_PASSWORD) {
                    pwdReset = fetchPwdResetFromLDAP();
                    return;
                }

                super.removeRequiredAction(action);
            }

            private boolean fetchPwdResetFromLDAP() {
                LDAPObject ldapUser = PasswordPolicyPwdResetMapper.this.ldapProvider.loadLDAPUserByUsername(realm,
                        getUsername());
                if (ldapUser != null) {
                    String pwdResetAsString = ldapUser.getAttributeAsString(LDAPConstants.PPOLICY_PWD_RESET);
                    return pwdResetAsString != null && Boolean.parseBoolean(pwdResetAsString);
                }

                return false;
            }
        };

        return delegate;
    }

    @Override
    public void beforeLDAPQuery(LDAPQuery query) {
        query.addReturningLdapAttribute(LDAPConstants.PPOLICY_PWD_RESET);
    }

}
