# Changelog

## v1.3.0

* Bug fixes
  * made sure that `django_salt` does not contain a '$' sign, which would break `verify_pass`
* Changes
  * changed minimum salt length to 0 bytes and added warning for salts between 0 and 8 bytes long
  * updated documentation about salt length with more information about the minimum recommended value

## v1.2.0

* Changes
  * using Comeonin v5.3, which changes `add_hash` so that it does NOT set the password to nil

## v1.1.0

* Enhancements
  * Updated documentation - in line with updates to Comeonin v5.2

## v1.0.0

* Enhancements
  * Updated to use Comeonin behaviour

## v0.12.0

* Changes
  * Created separate Pbkdf2 library
