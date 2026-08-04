package org.shredzone.acme4j.provider;

import java.net.URI;

import org.shredzone.acme4j.connector.NetworkSettings;
import org.shredzone.acme4j.connector.Connection;

public interface AcmeProviderManagingHttpClient {
    /**
     * Creates a {@link Connection} for communication with the ACME server.
     * 
     * Unlike the connect function for a regular {@link AcmeProvider},
     * using an implementation of {@link AcmeProviderManagingHttpClient} will
     * leave the responsiblity of managing the HTTP connection to the ACME
     * server up to the implementation.
     *
     * @param serverUri
     *         Server {@link URI}
     * @param networkSettings
     *         {@link NetworkSettings} to be used for the connection
     * @return {@link Connection} that was generated
     * @since 4.0.0
     */
    Connection connect(URI serverUri, NetworkSettings networkSettings);
}
