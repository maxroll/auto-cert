# auto-cert by Maxroll.gg
----------------

## Terminology

### Secret backend
Any secret backend that can store secrets. mainly used to store the private key

### Requestor / ACME Provider
Issues certificates

### Runner
Runs an action after a certificate is requested or renewed

## Purpose
Generates letsencrypt secrets, uses secretmanager for storage.
Replicates secrets to different providers such as CDN providers.

Currently supports the following secret backends:

* GCP SecretManager

Currently support the following runners:

* BunnyCDN

## TODO

* Add tests