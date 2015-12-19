# HTTP Challenge

After authorizing the challenge, `HttpChallenge` provides two strings:

```java
HttpChallenge challenge = auth.findChallenge(HttpChallenge.TYPE);
challenge.authorize(account);

String token = challenge.getToken();
String content = challenge.getAuthorization();
```

`token` is the name of the file that will be requested by the CA server. It must contain the `content` string, without any leading or trailing white spaces or line breaks. The `Content-Type` header must be either `text/plain` or absent.

The expected path is (assuming that `${domain}` is your domain and `${token}` is the token):

```
http://${domain}/.well-known/acme-challenge/${token}
```

The challenge is completed when the CA was able to download that file and found `content` in it.
