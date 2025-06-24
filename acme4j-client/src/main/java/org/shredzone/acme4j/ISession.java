package org.shredzone.acme4j;

import edu.umd.cs.findbugs.annotations.Nullable;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.shredzone.acme4j.connector.Connection;
import org.shredzone.acme4j.connector.NetworkSettings;
import org.shredzone.acme4j.connector.Resource;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.provider.AcmeProvider;

import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.time.ZonedDateTime;
import java.util.Locale;
import java.util.Optional;

public interface ISession {
    Login login(URL accountLocation, KeyPair accountKeyPair);

    URI getServerUri();

    @Nullable
    String getNonce();

    void setNonce(@Nullable String nonce);

    @Nullable
    Locale getLocale();

    void setLocale(@Nullable Locale locale);

    String getLanguageHeader();

    @SuppressFBWarnings("EI_EXPOSE_REP")    // behavior is intended
    NetworkSettings networkSettings();

    AcmeProvider provider();

    Connection connect();

    URL resourceUrl(Resource resource) throws AcmeException;

    Optional<URL> resourceUrlOptional(Resource resource) throws AcmeException;

    Metadata getMetadata() throws AcmeException;

    @Nullable
    ZonedDateTime getDirectoryLastModified();

    void setDirectoryLastModified(@Nullable ZonedDateTime directoryLastModified);

    @Nullable
    ZonedDateTime getDirectoryExpires();

    void setDirectoryExpires(@Nullable ZonedDateTime directoryExpires);

    boolean hasDirectory();

    void purgeDirectoryCache();
}
