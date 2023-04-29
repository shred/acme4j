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
 * This package contains all exceptions that can be thrown by acme4j.
 * <p>
 * {@link org.shredzone.acme4j.exception.AcmeException} is the root exception, and other
 * exceptions are derived from it.
 * <p>
 * Some methods that do lazy-loading of remote resources may throw a runtime
 * {@link org.shredzone.acme4j.exception.AcmeLazyLoadingException} instead, so the API is
 * not polluted with checked exceptions on every getter.
 */
@ReturnValuesAreNonnullByDefault
@DefaultAnnotationForParameters(NonNull.class)
@DefaultAnnotationForFields(NonNull.class)
package org.shredzone.acme4j.exception;

import edu.umd.cs.findbugs.annotations.DefaultAnnotationForFields;
import edu.umd.cs.findbugs.annotations.DefaultAnnotationForParameters;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.ReturnValuesAreNonnullByDefault;
