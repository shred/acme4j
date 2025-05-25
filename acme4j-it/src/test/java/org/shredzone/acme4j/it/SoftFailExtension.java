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

import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.TestExecutionExceptionHandler;
import org.opentest4j.TestAbortedException;
import org.shredzone.acme4j.exception.AcmeException;

/**
 * Aborts a @{@link SoftFail} annotated test when an {@link AcmeException} is thrown.
 */
public class SoftFailExtension implements TestExecutionExceptionHandler {
    @Override
    public void handleTestExecutionException(ExtensionContext ctx, Throwable ex)
            throws Throwable {
        if (ex instanceof AcmeException) {
            throw new TestAbortedException("SOFT FAIL: " + ctx.getDisplayName()
                    + " - " + ex.getMessage(), ex);
        }
        throw ex;
    }
}
