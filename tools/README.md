## Create a key pair

For ED25519 (the original Chrome format):

```
$ openssl genpkey -algorithm ED25519 > /path/to/private-key.pem
$ openssl pkey -in /path/to/private-key -pubout > /path/to/public-key.pem
```

For ECDSA with P-256:

```
$ openssl ecparam -genkey -name prime256v1 -out /path/to/private-key.pem
$ openssl ec -in /path/to/private-key -pubout -out /path/to/public-key.pem
$ openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in /path/to/private-key.pem -out /path/to/private-key.pkcs8.pem
```

### Dump it for C or Rust as needed

```
$ dump /path/to/public/key [--c]
```

## Make and verify an origin trial token

```
$ mktoken --origin https://foobar.org:345 --feature "foobar" --expiry "$(date --date="09:00 next Fri" -R)" --sign /path/to/private/key
$ verify <token> -p test-keys/test.pub
```

## Google Cloud Verification and Signing

See also: https://cloud.google.com/kms/docs/create-validate-signatures

### Set up the GCloud project

```
$ gcloud auth login
$ gcloud config set project moz-fx-origin-tr-nonprod-c6af
$ # Use the production project if appropriate instead
```

### Get the public key

```
$ # Use -prod instead of -dev for the production key
$ gcloud kms keys versions get-public-key 1                               \
    --key origin-trials-dev --keyring origin-trials-dev --location global \
    --output-file dev.pub
```

You can then dump the raw key or verify tokens as described above with the
`dump` command.

### Sign a token using GCloud

```
$ mktoken --origin https://foobar.org:345 --feature "foobar"              \
    --expiry "$(date --date="09:00 next Fri" -R)"                         \
    --gcloud-sign 1:origin-trials-dev:origin-trials-dev:global
```

### Verify a token

You just need to verify it with the public key downloaded above as for any other
key:

```
$ verify <token> -p dev.pub
```
