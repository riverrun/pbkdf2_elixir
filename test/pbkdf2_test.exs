defmodule Pbkdf2Test do
  use ExUnit.Case
  doctest Pbkdf2

  test "hash_pwd_salt only contains alphanumeric characters" do
    assert String.match?(Pbkdf2.hash_pwd_salt("password"), ~r/^[A-Za-z0-9.$\/\-]*$/)

    assert String.match?(
             Pbkdf2.hash_pwd_salt("password", format: :django),
             ~r/^[A-Za-z0-9+$_=\/]*$/
           )

    assert String.match?(Pbkdf2.hash_pwd_salt("password", format: :hex), ~r/^[A-Za-z0-9]*$/)
  end

  test "hashes with different lengths are correctly created and verified" do
    hash = Pbkdf2.hash_pwd_salt("password", length: 128)
    assert Pbkdf2.verify_pass("password", hash) == true
    django_hash = Pbkdf2.hash_pwd_salt("password", length: 128, format: :django)
    assert Pbkdf2.verify_pass("password", django_hash) == true
  end

  test "hashes with different number of rounds are correctly created and verified" do
    hash = Pbkdf2.hash_pwd_salt("password", rounds: 100_000)
    assert Pbkdf2.verify_pass("password", hash) == true
    django_hash = Pbkdf2.hash_pwd_salt("password", rounds: 10000, format: :django)
    assert Pbkdf2.verify_pass("password", django_hash) == true
  end
end
