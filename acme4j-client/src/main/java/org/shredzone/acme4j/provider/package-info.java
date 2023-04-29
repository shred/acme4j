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
 * Acme Providers are the link between acme4j and the ACME server. They know how to
 * connect to their server, and how to set up HTTP connections.
 * <p>
 * {@link org.shredzone.acme4j.provider.AcmeProvider} is the root interface.
 * {@link org.shredzone.acme4j.provider.AbstractAcmeProvider} is an abstract
 * implementation of the most elementary methods. Most HTTP based providers will extend
 * from {@link org.shredzone.acme4j.provider.GenericAcmeProvider} though.
 * <p>
 * Provider implementations must be registered with Java's
 * {@link java.util.ServiceLoader}.
 */
@ReturnValuesAreNonnullByDefault
@DefaultAnnotationForParameters(NonNull.class)
@DefaultAnnotationForFields(NonNull.class)
package org.shredzone.acme4j.provider;

import edu.umd.cs.findbugs.annotations.DefaultAnnotationForFields;
import edu.umd.cs.findbugs.annotations.DefaultAnnotationForParameters;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.ReturnValuesAreNonnullByDefault;
