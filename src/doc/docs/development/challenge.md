# ACME Challenge

RFC 8555 only specifies the [`http-01`](../challenge/http-01.md) and [`dns-01`](../challenge/dns-01.md) challenges. _acme4j_ permits to add further challenge types, which are either generic or provider proprietary.

## Provider Proprietary Challenges

If your provider requires a challenge that is too special for generic use, you can add it to your provider package and generate it via `createChallenge(Login, JSON)`. See the [Individual Challenges](provider.md#individual-challenges) section of the [ACME Provider](provider.md) chapter.

## Generic Challenges

Starting with _acme4j_ v2.12, generic challenges can be added globally using Java's `ServiceLoader` mechanism.

Your implementation must provide a challenge provider that implements the `org.shredzone.acme4j.provider.ChallengeProvider` interface and is annotated with a `org.shredzone.acme4j.provider.ChallengeType` annotation giving the name of your challenge. The only method `Challenge create(Login login, JSON data)` must return a new instance of your `Challenge` class which is initialized with the challenge data given in the `data` JSON structure.

A simple example of a `ChallengeProvider` is:

```java
@ChallengeType("my-example-01")
public class MyExample01ChallengeProvider implements ChallengeProvider {
    @Override
    public Challenge create(Login login, JSON data) {
        return new MyExample01Challenge(login, data);
    }
}
```

Note that you cannot replace predefined challenges, or another challenge implementation of the same type. If your `@ChallengeType` is already known to _acme4j_, an exception will be thrown on initialization time.

The `ChallengeProvider` implementation needs to be registered with Java's `ServiceLoader`. In the `META-INF/services` path of your project, create a file `org.shredzone.acme4j.provider.ChallengeProvider` and write the fully qualified class name of your implementation into that file. If you use Java modules, there must also be a `provides` section in your `module-info.java`, e.g.:

```java
provides org.shredzone.acme4j.provider.ChallengeProvider
    with org.example.acme.challenge.MyExample01ChallengeProvider;
```

The `acme4j-smime` module is implemented that way, and also serves as an example of how to add generic challenges.

## Adding your generic Challenge to _acme4j_

After you completed your challenge code, you can send in a pull request and apply for inclusion in the _acme4j_ code base. If it is just a simple challenge implementation, you can apply for inclusion in the `acme4j-client` module. If the challenge is complex, or requires further dependencies, please create a separate module.

These preconditions must be met:

* The challenge must be of common interest. If the challenge is only useful to your CA, better publish an own Java package instead.
* The specification of the challenge must be available to the public. It must be downloadable free of charge and without prior obligation to register.
* Your source code must be published under the terms of [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0).
* You have the permission of all trademark holders involved, to use their trademarks in the source codes, and package names.

The _acme4j_ development team reserves the right to reject your pull request, without giving any reason.

If you cannot meet these preconditions (or if your pull request was rejected), you can publish a JAR package of your _acme4j_ challenge yourself. Due to the plug-in nature of _acme4j_ challenges, it is sufficient to have that package in the Java classpath at runtime. There is no need to publish the source code.
