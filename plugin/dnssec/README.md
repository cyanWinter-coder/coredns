# dnssec

## Name

*dnssec* - enables on-the-fly DNSSEC signing of served data.

## Description

With *dnssec*, any reply that doesn't (or can't) do DNSSEC will get signed on the fly. Only replies to
queries with the DO bit set are signed; a reply to a client that did not set DO is returned as-is.
Authenticated denial of existence is implemented with NSEC black lies. Using ECDSA as an algorithm is
preferred as this leads to smaller signatures (compared to RSA). NSEC3 is *not* supported.

Signatures are cached per RRset. The cache key includes the RRset content, the wildcard owner a
wildcard expansion was synthesized from (if any) and the key tags of the configured keys, and entries
live for the RRset's TTL. The key tags in the key mean a key rollover never serves signatures made by
a previous key set; while both the old and the new key are configured (the rollover window), the
key set is unchanged and signatures of both keys are served. Cached signatures are also selected by
key tag, so removing a key drops only that key's signatures.

If a reply cannot be signed — no key applies to an RRset, an algorithm is not supported, or the key
fails to produce a signature — *dnssec* returns SERVFAIL and logs the reason instead of serving the
RRset unsigned. Unsigned data would look insecure or bogus to a validating client.

To generate an NSEC proof for an authoritative NODATA response (the name exists but has no records of
the requested type), *dnssec* requires the zone's SOA to be the only record in the authority section.
When using *forward*, the upstream server must supply that SOA.

When the *file* plugin served the reply from a wildcard, it records the wildcard owner as
`zone/wildcard` metadata. Enable the *metadata* plugin for *dnssec* to pick that up and produce
RRSIGs whose Labels field covers the wildcard owner (RFC 4034 section 3.1.3); without it the
wildcard expansion is signed as a literal name.

This plugin can only be used once per Server Block.

## Syntax

~~~
dnssec [ZONES... ] {
    key file|aws_secretsmanager KEY...
    cache_capacity CAPACITY
}
~~~

The signing behavior depends on the keys specified. If multiple keys are specified of which there is
at least one key with the SEP bit set and at least one key with the SEP bit unset, signing will happen
in split ZSK/KSK mode. DNSKEY records will be signed with all keys that have the SEP bit set. All other
records will be signed with all keys that do not have the SEP bit set.

In any other case, each specified key will be treated as a CSK (common signing key), forgoing the
ZSK/KSK split. All signing operations are done online.
Authenticated denial of existence is implemented with NSEC black lies. Using ECDSA as an algorithm
is preferred as this leads to smaller signatures (compared to RSA). NSEC3 is *not* supported.

As the *dnssec* plugin can't see the original TTL of the RRSets it signs, it will always use 3600s
as the value. The signature cache follows the TTL of the RRset being signed (which for data coming
from *file* is the zone's TTL).

If multiple *dnssec* plugins are specified in the same zone, the last one specified will be
used.

* **ZONES** zones that should be signed. If empty, the zones from the configuration block
    are used.

* `key file` indicates that **KEY** file(s) should be read from disk. When multiple keys are specified, RRsets
  will be signed with all keys. Generating a key can be done with `dnssec-keygen`: `dnssec-keygen -a
  ECDSAP256SHA256 <zonename>`. A key created for zone *A* can be safely used for zone *B*. The name of the
  key file can be specified in one of the following formats

    * basename of the generated key `Kexample.org+013+45330`
    * generated public key `Kexample.org+013+45330.key`
    * generated private key `Kexample.org+013+45330.private`

* `key aws_secretsmanager` indicates that **KEY** secret(s) should be read from AWS Secrets Manager. Secret
  names or ARNs may be used. After generating the keys as described in the `key file` section, you can
  store them in AWS Secrets Manager using the following AWS CLI v2 command:

  ```sh
  aws secretsmanager create-secret --name "Kexample.org.+013+45330" \
  --description "DNSSEC keys for example.org" \
  --secret-string "$(jq -n --arg key "$(cat Kexample.org.+013+45330.key)" \
  --arg private "$(cat Kexample.org.+013+45330.private)" \
  '{key: $key, private: $private}')"
  ```

  This command reads the contents of the `.key` and `.private` files, constructs a JSON object, and stores it
  as a new secret in AWS Secrets Manager with the specified name and description. CoreDNS will then fetch
  the key data from AWS Secrets Manager when using the `key aws_secretsmanager` directive.

  [AWS SDK for Go V2](https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/configure-auth.html) is used
  for authentication with AWS Secrets Manager. Make sure the provided AWS credentials have the necessary
  permissions (e.g., `secretsmanager:GetSecretValue`) to access the specified secrets in AWS Secrets Manager.

* `cache_capacity` indicates the capacity of the cache. The dnssec plugin uses a cache to store
  RRSIGs. The default for **CAPACITY** is 10000.

## Metrics

If monitoring is enabled (via the *prometheus* plugin) then the following metrics are exported:

* `coredns_dnssec_cache_entries{server, type}` - total elements in the cache, type is "signature".
* `coredns_dnssec_cache_hits_total{server}` - Counter of cache hits.
* `coredns_dnssec_cache_misses_total{server}` - Counter of cache misses.

The label `server` indicated the server handling the request, see the *metrics* plugin for details.

## Examples

Sign responses for `example.org` with the key "Kexample.org.+013+45330.key".

~~~ corefile
example.org {
    dnssec {
        key file Kexample.org.+013+45330
    }
    whoami
}
~~~

Sign responses for `example.org` with the key stored in AWS Secrets Manager under the secret name
"Kexample.org.+013+45330".

~~~
example.org {
    dnssec {
        key aws_secretsmanager Kexample.org.+013+45330
    }
    whoami
}
~~~

Sign responses for a kubernetes zone with the key "Kcluster.local+013+45129.key".

~~~
cluster.local {
    kubernetes
    dnssec {
      key file Kcluster.local+013+45129
    }
}
~~~
