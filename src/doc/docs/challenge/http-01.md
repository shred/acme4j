# http-01 Challenge

With the `http-01` challenge, you prove to the CA that you are able to control the web site content of the domain to be authorized, by making a file with a signed content available at a given path.

`Http01Challenge` provides two strings:

```java
Http01Challenge challenge = auth.findChallenge(Http01Challenge.class);
String domain = auth.getIdentifier().getDomain();

String token = challenge.getToken();
String content = challenge.getAuthorization();
```

`token` is the name of the file that will be requested by the CA server. It must contain the `content` string, without any leading or trailing white spaces or line breaks. The `Content-Type` header must be either `text/plain` or absent.

The expected path is (assuming that `${domain}` is the domain to be authorized, and `${token}` is the token):

```
http://${domain}/.well-known/acme-challenge/${token}
```

The validation was successful if the CA was able to download that file and found `content` in it.

!!! note
    The request is sent to port 80 only, but redirects are followed. If your domain has multiple IP addresses, the CA randomly selects some of them. There is no way to choose a different port or a fixed IP address.

Your server should be able to handle multiple requests to the challenge. The ACME server may check your response multiple times, and from different IPs. Also keep your response available until the `Authorization` status has changed to `VALID` or `INVALID`.
