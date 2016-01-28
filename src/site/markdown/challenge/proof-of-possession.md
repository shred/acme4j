# Proof of Possession

With the Proof of Possesion challenge, you prove to the CA that you are able to provide a verification document that is signed with a key that is known to the server. The main purpose of this challenge is to transfer the authorization of a domain to your account.

The challenge object contains a list of `X509Certificate`s that are already known to the CA:

```java
ProofOfPossessionChallenge challenge =
        auth.findChallenge(ProofOfPossessionChallenge.TYPE);
Collection<X509Certificate> certificates = challenge.getCertificates();
```

In the next step, the _current owner of the domain_ authorizes the challenge, by signing it with a key pair that corresponds to one of the `certificates`:

```java
Registration ownerRegistration = ... // Registration of the domain owner
KeyPair domainKeyPair = ... // Key pair matching a certificate
String domain = ... // Domain to authorize

challenge.authorize(ownerRegistration, domainKeyPair, domain);
```

The challenge is completed when the domain is associated with the account of the `ownerRegistration`, and the `domainKeyPair` matches one of the `certificates`.

## Importing a Validation

A problem with this challenge is that a third party needs to provide the account and domain key pairs for authorization.

There is a way to prepare the validation externally, and import a validation document into the challenge in a separate step. The validation document is signed by the domain owner, but does not contain any private keys.

_acme4j_ offers a `ValidationBuilder` class for generating the validation document:

```java
Registration ownerRegistration = ... // Registration of the domain owner
KeyPair domainKeyPair = ... // Key pair matching a certificates

ValidationBuilder vb = new ValidationBuilder();
vb.domain("example.org");
String json = vb.sign(ownerRegistration, domainKeyPair);
```

This `json` string can be transported (e.g. via email) and then imported into the challenge:

```java
String json = ... // validation document

ProofOfPossessionChallenge challenge =
        auth.findChallenge(ProofOfPossessionChallenge.TYPE);
challenge.importValidation(json);
```

The challenge is authorized now, and is ready to be executed.
