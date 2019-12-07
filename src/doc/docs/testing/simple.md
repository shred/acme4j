# Simple Unit Tests

`org.shredzone.acme4j.mock.MockAcmeServer` is the central class of the mock framework. It mocks an ACME server instance.

So, the first thing to do in every unit test is to create an instance of this server:

```java
MockAcmeServer server = new MockAcmeServer();
```

The server provides a `Session` instance that can be used to access the server.

```java
Session session = server.createSession();
```

!!! note
    This is the only way to create a `Session` that is connected to the mock server! Even though the mock server seems to have an ACME URI (`"acme://mock/"`), you cannot create a new `Session` by providing this URI.

`MockAcmeServer` are lightweight. You can just create a new instance for each unit test, and throw it away at the end of the test.

## Basic Usage

You can use the Session as if you were connected to a real ACME server. For example, this is how to create a new account:

```java
KeyPair keyPair = KeyPairUtils.createKeyPair(2048);
URI email = URI.create("mailto:foo@example.com");

Account account = new AccountBuilder()
        .addContact(email)
        .agreeToTermsOfService()
        .useKeyPair(keyPair)
        .create(session);

assertThat(account.getLocation(), is(notNullValue()));
assertThat(account.getStatus(), is(Status.VALID));
assertThat(account.getContacts().size(), is(1));
assertThat(account.getContacts().get(0), is(email));
```

## Mock Resources

The mock server manages a mock resource for each resource that is created in the test. For example, an `Account` on your client side is matched by a `MockAccount` instance on server side. It reflects the server's status of that account.

You can get the `MockAccount` from the `MockAcmeServer` in different ways:

```java
// Get the MockAccount that is matching your Account instance
MockAccount mockAccount = server.getMockOf(account);

// Get the MockAccount by the public key
MockAccount mockAccountByKey = server.findAccount(keyPair.getPublic()).get();

// Just get all the MockAccounts that are currently existing
List<MockAccount> allMockAccounts = server.getAccounts();
```

The `MockAccount` reflects the state of your account on the server side:

```java
assertThat(mockAccount.getContacts().size(), is(1));
assertThat(mockAccount.getContacts().get(0), is(email));
```

You can manipulate the `MockAccount` at will. For example, you can change its status:

```java
// By default, your account is VALID
assertThat(account.getStatus(), is(Status.VALID));

// We are going to change that now...
mockAccount.setStatus(Status.REVOKED);

// Your local Account object still holds the cached status!
assertThat(account.getStatus(), is(Status.VALID));

// Update it, so the new status is fetched from the server
account.update();
assertThat(account.getStatus(), is(Status.REVOKED));
```

!!! note
    You can always enforce a resource status by setting the desired status value via `setStatus()`. If you set no status (or set the status to `null`), the mock server deduces the status from the current state of the resource. For most test cases, you can just leave the status untouched and let the mock server take care for it.

## Setting Up Mock Resources

Mock resources also work the other way around. You can create them on the server side, and populate the mock server with resources before running a test against it.

```java
MockAcmeServer server = new MockAcmeServer();

// Create a key pair and contact address
KeyPair keyPair = KeyPairUtils.createKeyPair(2048);
URI email = URI.create("mailto:foo@example.com");

// Create a new MockAccount
MockAccount mockAccount = server.createAccount(keyPair.getPublic());
mockAccount.setTermsOfServiceAgreed(true);
mockAccount.getContact().add(email);
URL accountLocation = mockAccount.getLocation();

// Your account is ready, just use it in your test...
Session session = server.createSession();
Login login = session.login(accountLocation, keyPair);
Account account = login.getAccount();
assertThat(account.getContacts().get(0), is(email));
```

The entire mock server can be prepared for a test that way. For example, if you want to write a unit test for a method that only downloads an existing ceritificate, you can construct a server with all the necessary resources being already present. When your unit test is executed, it finds a mock server that is ready for certificate downloading.

You will find more examples in the [example package](https://github.com/shred/acme4j/tree/master/acme4j-mock/src/test/java/org/shredzone/acme4j/mock/example) at the acme4j-mock unit tests.

## Shortcuts

The mock server is not a true ACME server. The advantage is that you can prepare it with a minimal effort, even if the result would not be possible on a real server. For example, if you want to test a method that only needs an `Order` resource, you can skip setting up an account, authorizations and challenges.

This is all you need to create a mock server with an order:

```java
MockAcmeServer server = new MockAcmeServer();
MockOrder mockOrder = server.createOrder(Identifier.dns("example.com"));
```

You can also generate a `Login` without having to set up an account. The mock server will create an empty account with a random key pair for you.

```java
Login login = server.createLogin();
Session session = login.getSession();
```

Now bind the location of the mock order to the `Login`, and get an `Order` resource that is ready for testing:

```java
Order order = login.bindOrder(mockOrder.getLocation());
```

All of this took just five lines of code.
