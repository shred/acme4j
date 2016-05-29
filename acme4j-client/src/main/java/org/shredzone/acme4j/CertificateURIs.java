package org.shredzone.acme4j;

import java.net.URI;

/**
 * Represents the URIs returned by a certificate request
 * 
 * @author cargy
 *
 */
public class CertificateURIs {
    
    private final URI certUri;
    private final URI chainCertUri;
    
    public CertificateURIs(URI certUri, URI chainCertUri) {
	this.certUri = certUri;
	this.chainCertUri = chainCertUri;
    }

    /**
     * The URI from which the client may fetch the certificate
     * 
     * @return
     * 		{@link URI} the certificate can be downloaded from
     */
    public URI getCertUri() {
	return certUri;
    }

    /**
     * The URI from which the client may fetch a chain of CA certificates
     * 
     * @return
     * 		{@link URI} the certificate chain can be downloaded from
     */
    public URI getChainCertUri() {
	return chainCertUri;
    }

}
