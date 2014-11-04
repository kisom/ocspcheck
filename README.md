# OCSP check

This is a program to check the revocation status of a certificate against
an OCSP server. It will use the OCSP URLs in the certificate provided.

## Usage

```
ocspcheck [-f certificate] [-i issuer] [-s server] [server]

    -f certificate      This is the certificate that should be
                        checked. It defaults to standard input.
    -i issuer           If this is not empty and the OCSP response
                        contains a certificate, the certificate
                        will be written to this file.
    -s server		    This manually specifies an OCSP server
                        to use.
```

Instead of providing a certificate, a server name can be provided on
the command line:

```
$ ocspcheck kyleisom.net
fetching certificate from kyleisom.net:443
OCSP stapled response
        Certificate status: good
        Certificate serial number: 245888128265169107985960673048326379322
        Status produced at 2014-11-03 22:43:39 +0000 UTC
        Current update: 2014-11-03 22:43:39 +0000 UTC
        Next update: 2014-11-07 22:43:39 +0000 UTC
```


