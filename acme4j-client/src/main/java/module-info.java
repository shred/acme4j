/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2020 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

/**
 * This is the main module of the acme4j client.
 */
module org.shredzone.acme4j {
    requires static com.github.spotbugs.annotations;
    requires java.net.http;
    requires org.bouncycastle.pkix;
    requires org.bouncycastle.provider;
    requires org.jose4j;
    requires org.slf4j;

    exports org.shredzone.acme4j;
    exports org.shredzone.acme4j.challenge;
    exports org.shredzone.acme4j.connector;
    exports org.shredzone.acme4j.exception;
    exports org.shredzone.acme4j.provider;
    exports org.shredzone.acme4j.toolbox;
    exports org.shredzone.acme4j.util;

    uses org.shredzone.acme4j.provider.AcmeProvider;
    uses org.shredzone.acme4j.provider.ChallengeProvider;

    provides org.shredzone.acme4j.provider.AcmeProvider
            with org.shredzone.acme4j.provider.GenericAcmeProvider,
                 org.shredzone.acme4j.provider.actalis.ActalisAcmeProvider,
                 org.shredzone.acme4j.provider.google.GoogleAcmeProvider,
                 org.shredzone.acme4j.provider.letsencrypt.LetsEncryptAcmeProvider,
                 org.shredzone.acme4j.provider.pebble.PebbleAcmeProvider,
                 org.shredzone.acme4j.provider.sslcom.SslComAcmeProvider,
                 org.shredzone.acme4j.provider.zerossl.ZeroSSLAcmeProvider;
}
