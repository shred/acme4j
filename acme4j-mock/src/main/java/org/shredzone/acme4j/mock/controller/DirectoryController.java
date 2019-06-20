/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2019 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.mock.controller;

import java.net.URL;

import javax.annotation.ParametersAreNonnullByDefault;

import org.shredzone.acme4j.mock.connection.Result;
import org.shredzone.acme4j.mock.model.MockDirectory;

/**
 * A {@link Controller} that returns the directory structure.
 *
 * @since 2.8
 */
@ParametersAreNonnullByDefault
public class DirectoryController implements Controller {
    private final MockDirectory directory;

    /**
     * Creates a new {@link DirectoryController}.
     *
     * @param directory
     *         {@link MockDirectory} this controller is bound to
     */
    public DirectoryController(MockDirectory directory) {
        this.directory = directory;
    }

    /**
     * Returns the directory structure.
     *
     * {@inheritDoc}
     */
    @Override
    public Result doSimpleRequest(URL requestUrl) {
        return new Result(directory.toJSON());
    }

}
