# Resources and Persistence

All CA related resources are derived from the `AcmeResource` class:

* `Account`: Represents your account
* `Authorization`: Authorization of a domain or identifier
* `Certificate`: A certificate
* `Challenge` (and subclasses): Challenge to proof domain ownership
* `Order`: A certificate order
* `RenewalInfo`: Renewal information

These classes reflect the state of the corresponding resource on the ACME server side. They also keep a copy of the current resource state that can be updated via `update()`. The only exception is the `Certificate` resource, which will never change its state and thus does not need to be updated.

## Resource Location

All resources possess a unique resource URL on the CA server. To get that URL, invoke the `getLocation()` method. This is the best way to retrieve a permanent resource reference for local persistence (e.g. in a database).

## Resource Binding

To revive an `AcmeResource` object from its location URL, you can bind it to your `Login` by using the resource location URL and the corresponding method:

* `Login.bindAuthorization()` takes an authorization URL and returns the corresponding `Authorization` object.
* `Login.bindCertificate()` takes a certificate URL and returns the corresponding `Certificate` object.
* `Login.bindOrder()` takes an order URL and returns the corresponding `Order` object.
* `Login.bindRenewalInfo()` takes an renewal info URL and returns the corresponding `RenewalInfo` object.

There are two methods for binding a `Challenge`:

* `Login.bindChallenge(URL location)` binds to a challenge URL and returns a `Challenge` instance. You will need to check yourself if the `Challenge` is of the expected type, and eventually cast it to the correct type.
* `bindChallenge(URL location, Class type)` is similar to the method above, but will do the casting for you. You will get the challenge object in your expected type. If the challenge at the location is of a different type, an `AcmeProtocolException` will be thrown.

There is no way to bind an `Account`. To retrieve your account resource, simply invoke `Login.getAccount()`.

!!! note
    You can only bind resources that belong to your account.

## Serialization

All resource objects are serializable, so the current state of the object can also be frozen by Java's serialization mechanism.

However the `Login` that the object is bound to is _not_ serialized! This is because in addition to volatile data, the `Login` object also holds a copy of your private key. Not serializing it prevents you from accidentally exposing your private key in a place with lowered access restrictions.

After deserialization, an object is not bound to a `Login` yet. It is required to rebind it by invoking the `rebind()` method of the resource object.

!!! note
    Serialization is only meant for short term storage at runtime, not for long term persistence. For long term persistence, always store the location URL of the resource, then bind it at later time like mentioned above.

!!! warning
    Do not share serialized data between different versions of _acme4j_.
