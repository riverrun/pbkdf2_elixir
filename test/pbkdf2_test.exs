defmodule Pbkdf2Test do
  use ExUnit.Case
  doctest Pbkdf2

  import Pbkdf2TestHelper

  test "hashing and checking passwords" do
    wrong_list = ["aged2h$ru", "2dau$ehgr", "rg$deh2au", "2edrah$gu", "$agedhur2", ""]
    password_hash_check("hard2guess", wrong_list)
  end

  test "hashing and checking passwords with characters from the extended ascii set" do
    wrong_list = ["eáé åöêô ëaäo", "aäôáö eéoêë å", " aöêôée oåäëá", "åaêöéäëeoô á ", ""]
    password_hash_check("aáåä eéê ëoôö", wrong_list)
  end

  test "hashing and checking passwords with non-ascii characters" do
    wrong_list = [
      "и Скл;лекьоток к олсомзь",
      "кеокок  зС омлслтььлок;и",
      "е  о оиькльлтСо;осккклзм",
      ""
    ]

    password_hash_check("Сколько лет; сколько зим", wrong_list)
  end

  test "hashing and checking passwords with mixed characters" do
    wrong_list = ["Я☕t☔s❤ùo", "o❤ Я☔ùrtês☕", " ùt❤o☕☔srêЯ", "ù☕os êt❤☔rЯ", ""]
    password_hash_check("Я❤três☕ où☔", wrong_list)
  end

  test "check password using check_pass, which uses the user map as input" do
    wrong_list = ["บดสคสััีวร", "สดรบัีสัคว", "สวดัรคบัสี", "ดรสสีวคบัั", "วรคดสัสีับ", ""]
    check_pass_check("สวัสดีครับ", wrong_list)
  end

  test "add hash to map and set password to nil" do
    wrong_list = ["êäöéaoeôáåë", "åáoêëäéôeaö", "aäáeåëéöêôo", ""]
    add_hash_check("aáåäeéêëoôö", wrong_list)
  end

  test "gen_salt length of salt" do
    assert byte_size(Pbkdf2.gen_salt()) == 16
    assert byte_size(Pbkdf2.gen_salt(32)) == 32
    assert byte_size(Pbkdf2.gen_salt(64)) == 64
  end

  test "hashes with different lengths are correctly verified" do
    hash = Pbkdf2.hash_pwd_salt("password", length: 128)
    assert Pbkdf2.verify_pass("password", hash) == true
    django_hash = Pbkdf2.hash_pwd_salt("password", length: 128, format: :django)
    assert Pbkdf2.verify_pass("password", django_hash) == true
  end

  test "add_hash and check_pass" do
    assert {:ok, user} = Pbkdf2.add_hash("password") |> Pbkdf2.check_pass("password")
    assert {:error, "invalid password"} =
             Pbkdf2.add_hash("pass") |> Pbkdf2.check_pass("password")
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
end
