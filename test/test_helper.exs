ExUnit.start()

defmodule Pbkdf2TestHelper do
  use ExUnit.Case

  def password_hash_check(password, wrong_list) do
    hash = Pbkdf2.hash_pwd_salt(password)
    assert Pbkdf2.verify_pass(password, hash)

    for wrong <- wrong_list do
      refute Pbkdf2.verify_pass(wrong, hash)
    end
  end

  def add_hash_check(password, wrong_list) do
    %{password_hash: hash, password: nil} = Pbkdf2.add_hash(password)
    assert Pbkdf2.verify_pass(password, hash)

    for wrong <- wrong_list do
      refute Pbkdf2.verify_pass(wrong, hash)
    end
  end

  def check_pass_check(password, wrong_list) do
    hash = Pbkdf2.hash_pwd_salt(password)
    user = %{id: 2, name: "fred", password_hash: hash}
    assert Pbkdf2.check_pass(user, password) == {:ok, user}
    assert Pbkdf2.check_pass(nil, password) == {:error, "invalid user-identifier"}

    for wrong <- wrong_list do
      assert Pbkdf2.check_pass(user, wrong) == {:error, "invalid password"}
    end
  end
end
