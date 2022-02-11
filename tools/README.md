## Create a key pair

```
$ openssl genpkey -algorithm ED25519 > /path/to/private-key
$ openssl pkey -in /path/to/private-key -pubout > /path/to/public-key
```

### Dump it for C or Rust as needed

```
$ dump /path/to/public/key [--c]
```

## Make and verify an origin trial token

```
$ mktoken --origin https://foobar.org:345 --feature "foobar" --expiry "$(date --date="09:00 next Fri" -R)" --sign /path/to/private/key
$ verify <token> test-keys/test.pub
```
