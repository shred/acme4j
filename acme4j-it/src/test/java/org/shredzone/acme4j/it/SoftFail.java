/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2025 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.it;

import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import org.junit.jupiter.api.extension.ExtendWith;
import org.shredzone.acme4j.exception.AcmeException;

/**
 * Marks a test to fail softly if an {@link AcmeException} is thrown. These are usually
 * integration tests that fail frequently because the external server has stability
 * issues.
 */
@Retention(RUNTIME)
@Target(METHOD)
@ExtendWith(SoftFailExtension.class)
public @interface SoftFail {
    /**
     * A human-readable reason why this test is marked as soft fail.
     */
    String value();
}
