defmodule Pbkdf2.Stats do
  @moduledoc """
  Module to provide statistics for the Pbkdf2 password hashing function.

  ## Configuring Pbkdf2

  The main configuration option for Pbkdf2 is the number of rounds that
  it uses. Increasing this value will increase the complexity, and time
  taken, of the Pbkdf2 function.
  """

  alias Pbkdf2.Base64

  @doc """
  Hash a password with Pbkdf2 and print out a report.

  This function hashes a password, and salt, with Pbkdf2.Base.hash_password/3
  and prints out statistics which can help you choose how to configure Pbkdf2.

  ## Options

  In addition to the options for Pbkdf2.Base.hash_password (rounds, output_fmt,
  digest and length), there are two options:

    * password - the password used
    * salt - the salt used
  """
  def report(opts \\ []) do
    password = Keyword.get(opts, :password, "password")
    salt = Keyword.get(opts, :salt, "somesaltSOMESALT")
    {exec_time, encoded} = :timer.tc(Pbkdf2.Base, :hash_password, [password, salt, opts])
    Pbkdf2.verify_pass(password, encoded)
    |> format_result(encoded, exec_time)
  end

  defp format_result(check, encoded, exec_time) do
    [_, alg, rounds, _, hash] = String.split(encoded, "$")
    IO.puts """
    Digest:\t\t#{alg}
    Digest length:\t#{Base64.decode(hash) |> byte_size}
    Hash:\t\t#{encoded}
    Rounds:\t\t#{rounds}
    Time taken:\t#{format_time(exec_time)} seconds
    Verification #{if check, do: "OK", else: "FAILED"}
    """
  end

  defp format_time(time) do
    Float.round(time / 1_000_000, 2)
  end
end
