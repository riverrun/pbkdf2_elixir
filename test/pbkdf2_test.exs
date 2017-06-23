defmodule Pbkdf2Test do
  use ExUnit.Case, async: false

  def hash_check_password(password, wrong1, wrong2, wrong3) do
    hash = Pbkdf2.hash_pwd_salt(password)
    assert Pbkdf2.verify_hash(hash, password) == true
    assert Pbkdf2.verify_hash(hash, wrong1) == false
    assert Pbkdf2.verify_hash(hash, wrong2) == false
    assert Pbkdf2.verify_hash(hash, wrong3) == false
  end

  test "pbkdf2 dummy check" do
    assert Pbkdf2.no_user_verify == false
  end

  test "hashing and checking passwords" do
    hash_check_password("password", "passwor", "passwords", "pasword")
    hash_check_password("hard2guess", "ha rd2guess", "had2guess", "hardtoguess")
  end

  test "hashing and checking passwords with characters from the extended ascii set" do
    hash_check_password("aáåäeéêëoôö", "aáåäeéêëoö", "aáåeéêëoôö", "aáå äeéêëoôö")
    hash_check_password("aáåä eéêëoôö", "aáåä eéê ëoö", "a áåeé êëoôö", "aáå äeéêëoôö")
  end

  test "hashing and checking passwords with non-ascii characters" do
    hash_check_password("Сколько лет, сколько зим", "Сколько лет,сколько зим",
    "Сколько лет сколько зим", "Сколько лет, сколько")
    hash_check_password("สวัสดีครับ", "สวัดีครับ", "สวัสสดีครับ", "วัสดีครับ")
  end

  test "hashing and checking passwords with mixed characters" do
    hash_check_password("Я❤três☕ où☔", "Я❤tres☕ où☔", "Я❤três☕où☔", "Я❤três où☔")
  end

  test "gen_salt length of salt" do
    assert byte_size(Pbkdf2.gen_salt) == 16
    assert byte_size(Pbkdf2.gen_salt(32)) == 32
    assert byte_size(Pbkdf2.gen_salt(64)) == 64
  end

  test "wrong input to verify_hash" do
    assert_raise ArgumentError, "Wrong type - password and salt should be strings", fn ->
      Pbkdf2.verify_hash("$pbkdf2-sha512$19000$JMT4nzOmVKrV.p/TmlMKwQ$jKbZHoPwUWBT08pjb/CnUZmFcB9JW4dsOzVkfi9X6Pdn5NXWeY.mhL1Bm4V9rjYL5ZfA32uh7Gl2gt5YQa/JCA", nil)
    end
  end

end
