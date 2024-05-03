package org.keycloak.policy;

import java.util.Objects;

import org.jboss.logging.Logger;
import org.keycloak.Config.Scope;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;

public class PasswordMinAgePolicyProviderFactory implements PasswordPolicyProviderFactory, PasswordPolicyProvider {

    public static final String PASSWORD_MIN_AGE_ID = "passwordMinAge";
    public static final Integer PASSWORD_MIN_AGE_DEFAULT = 24 * 60 * 60; // 1 day in seconds.

    private static final Logger logger = Logger.getLogger(PasswordMinAgePolicyProviderFactory.class);

    private KeycloakSession session;

    @Override
    public PasswordPolicyProvider create(KeycloakSession session) {
        this.session = session;
        return this;
    }

    @Override
    public void init(Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PASSWORD_MIN_AGE_ID;
    }

    @Override
    public PolicyError validate(RealmModel realm, UserModel user, String password) {
        // If the user is required to change the password, the password age is not checked.
        if (user.getRequiredActionsStream().anyMatch(UserModel.RequiredAction.UPDATE_PASSWORD.name()::equals)) {
            return null;
        }

        PasswordPolicy policy = session.getContext().getRealm().getPasswordPolicy();
        int passwordMinAgeMillis = (int) policy.getPolicyConfig(PASSWORD_MIN_AGE_ID) * 1000;
        long passwordAgeMillis = getPasswordAge(user);

        if (passwordMinAgeMillis > 0 && passwordAgeMillis != -1 && passwordAgeMillis < passwordMinAgeMillis) {
            logger.debugf("Password is too young to be changed for user %s (passwordAge=%d, minPasswordAge=%d)",
                    user.getUsername(), passwordAgeMillis, passwordMinAgeMillis);
            return new PolicyError("Password is too young to be changed", passwordAgeMillis, passwordMinAgeMillis);
        }

        return null;
    }

    private long getPasswordAge(UserModel user) {
        return user.credentialManager().getStoredCredentialsByTypeStream(PasswordCredentialModel.TYPE)
                .map(PasswordCredentialModel::createFromCredentialModel)
                .map(passwordCredential -> Time.currentTimeMillis() - passwordCredential.getCreatedDate())
                .min(Long::compare)
                .orElse(-1L);
    }

    @Override
    public PolicyError validate(String user, String password) {
        return null;
    }

    @Override
    public Object parseConfig(String value) {
        return parseInteger(value, -1);
    }

    @Override
    public String getDisplayName() {
        return "Minimum Password Age";
    }

    @Override
    public String getConfigType() {
        return PasswordPolicyProvider.INT_CONFIG_TYPE;
    }

    @Override
    public String getDefaultConfigValue() {
        return String.valueOf(PASSWORD_MIN_AGE_DEFAULT);
    }

    @Override
    public boolean isMultiplSupported() {
        return false;
    }

}
