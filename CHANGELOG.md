# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## master

* Enhancements
  * Allow all HMAC hash algorithms [supported in the crypto lib](https://erlang.org/doc/man/crypto.html#type-hmac_hash_algorithm).

## v1.4.0 - 2021-04-08

* Changes
  * updated hmac sha function to support the new crypto api in OTP 24

## v1.3.0 - 2021-01-08

* Bug fixes
  * made sure that `hash_pwd_salt/2` passes the `format: :django` option onto `gen_salt/1`
* Changes
  * changed minimum salt length to 0 bytes and added warning for salts between 0 and 8 bytes long
  * updated documentation about salt length with more information about the minimum recommended value
  * updated `gen_salt/1` to take a keyword list by default (an integer is also allowed for backwards compatibility)
* Deprecations
  * `Base.django_salt/1` has been deprecated - `gen_salt/1` can be used instead

## v1.2.0 - 2020-03-01

* Changes
  * using Comeonin v5.3, which changes `add_hash/2` so that it does NOT set the password to nil

## v1.1.0 - 2020-01-20

* Enhancements
  * Updated documentation - in line with updates to Comeonin v5.2

## v1.0.0 - 2019-02-19

* Enhancements
  * Updated to use Comeonin behaviour

## v0.12.0 - 2017-07-21

* Changes
  * Created separate Pbkdf2 library
