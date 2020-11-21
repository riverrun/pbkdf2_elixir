defmodule Pbkdf2Test do
  use ExUnit.Case
  doctest Pbkdf2

  import ExUnit.CaptureIO
  import Comeonin.BehaviourTestHelper

  test "implementation of Comeonin.PasswordHash behaviour" do
    password = Enum.random(ascii_passwords())
    assert correct_password_true(Pbkdf2, password)
    assert wrong_password_false(Pbkdf2, password)
  end

  test "Comeonin.PasswordHash behaviour with non-ascii characters" do
    password = Enum.random(non_ascii_passwords())
    assert correct_password_true(Pbkdf2, password)
    assert wrong_password_false(Pbkdf2, password)
  end

  test "add_hash function" do
    password = Enum.random(ascii_passwords())
    assert add_hash_creates_map(Pbkdf2, password)
  end

  test "check_pass function" do
    password = Enum.random(ascii_passwords())
    assert check_pass_returns_user(Pbkdf2, password)
    assert check_pass_returns_error(Pbkdf2, password)
    assert check_pass_nil_user(Pbkdf2)
  end

  test "gen_salt length of salt" do
    assert byte_size(Pbkdf2.gen_salt()) == 16
    assert byte_size(Pbkdf2.gen_salt(32)) == 32
    assert byte_size(Pbkdf2.gen_salt(64)) == 64
  end

  test "gen_salt prints warnings for salts that are too short" do
    assert capture_io(:stderr, fn -> Pbkdf2.gen_salt(7) end) =~
             "salt less than 8 bytes long is not recommended"
  end

  test "gen_salt raises if salt is too long" do
    assert_raise ArgumentError, fn ->
      Pbkdf2.gen_salt(1025)
    end
  end

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

  test "add_hash and check_pass" do
    assert {:ok, user} = Pbkdf2.add_hash("password") |> Pbkdf2.check_pass("password")
    assert {:error, "invalid password"} = Pbkdf2.add_hash("pass") |> Pbkdf2.check_pass("password")
    assert Map.has_key?(user, :password_hash)
  end

  test "add_hash with a custom hash_key and check_pass" do
    assert {:ok, user} =
             Pbkdf2.add_hash("password", hash_key: :encrypted_password)
             |> Pbkdf2.check_pass("password")

    assert {:error, "invalid password"} =
             Pbkdf2.add_hash("pass", hash_key: :encrypted_password)
             |> Pbkdf2.check_pass("password")

    assert Map.has_key?(user, :encrypted_password)
  end

  test "check_pass with custom hash_key" do
    assert {:ok, user} =
             Pbkdf2.add_hash("password", hash_key: :custom_hash)
             |> Pbkdf2.check_pass("password", hash_key: :custom_hash)

    assert Map.has_key?(user, :custom_hash)
  end

  test "check_pass with invalid hash_key" do
    {:error, message} =
      Pbkdf2.add_hash("password", hash_key: :unconventional_name)
      |> Pbkdf2.check_pass("password")

    assert message =~ "no password hash found"
  end

  test "check_pass with password that is not a string" do
    assert {:error, message} = Pbkdf2.add_hash("pass") |> Pbkdf2.check_pass(nil)
    assert message =~ "password is not a string"
  end

  # maybe move this to base_test + add comment stating reason for this test
  test "verify_pass can check hash with old django_salt" do
  end
end
