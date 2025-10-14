package net.ielpo.passkey;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

import com.google.auto.service.AutoService;

/**
 * @author Alberto Ielpo
 */
@AutoService(RealmResourceProviderFactory.class)
public class PasskeyProviderFactory implements RealmResourceProviderFactory {

    @Override
    public RealmResourceProvider create(KeycloakSession keycloakSession) {
        return new PasskeyProvider(keycloakSession);
    }

    @Override
    public void init(Config.Scope scope) {
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PasskeyConsts.PROVIDER_ID;
    }
}
