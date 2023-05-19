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

module org.shredzone.acme4j.it {
    requires org.shredzone.acme4j;

    requires com.github.spotbugs.annotations;
    requires org.apache.httpcomponents.httpclient;
    requires org.apache.httpcomponents.httpcore;

    exports org.shredzone.acme4j.it;
}
