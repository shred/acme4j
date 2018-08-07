# Contributing to _acme4j_

Thank you for taking your time to contribute!

## Acceptance Criteria

These criteria must be met for a successful pull request:

* Follow the [Style Guide](#style-guide).
* If you add code, remember to add [unit tests](#unit-tests) that test your code.
* All unit tests must run successfully.
* Integration tests should run successfully, unless there is a good reason (e.g. waiting for a pending change in Pebble).
* Your commits follow the [git commit](#git-commits) guide.
* You accept that your code is distributed under the terms of [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0).

## Style Guide

Our style guide bases on [Oracle's Code conventions for the Java Programming Language](http://www.oracle.com/technetwork/java/codeconventions-150003.pdf). These additional rules apply:

* Indentation is 4 spaces. Do not use tabs!
* Remove trailing spaces.
* Line length is 90 characters. You may exceed this length by a few characters if it is easier to read than a wrapped line.
* `if`, `for` and `while` statements always use blocks, even for a single statement.
* All types and methods must have a descriptive JavaDoc, except of `@Override` annotated methods. For plain getter and setter methods, `@param` and `@return` can be omitted.

## Unit Tests

More than 80% of the code is covered by unit tests, and we would like to keep it that way.

* Main functionalities must be covered by unit tests.
* Corner cases should be covered by unit tests.
* Common exception handling does not need to be tested.
* No tests are required for code that is not expected to be executed (e.g. `UnsupportedEncodingException` when handling utf-8, or the empty private default constructor of a utility class).
* Unit tests should not depend on external resources, as they might be temporarily unavailable at runtime.

There are no unit tests required for the `acme4j-example` and `acme4j-it` modules.

## git Commits

Good programming does not end with a clean source code, but should have pretty commits as well.

* Always put separate concerns into separate commits.
* If you have interim commits in your history, squash them with an interactive rebase before sending the pull request.
* Use present tense and imperative mood in commit messages ("fix bug #1234", not "fixed bug #1234").
* Always give meaningful commit messages (not just "bugfix").
* The commit message must be concise and should not exceed 50 characters. Further explanations may follow in subsequent lines, with an empty line as separator.
* Commits must compile and must not break unit tests.
