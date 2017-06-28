defmodule Pbkdf2.Stats do
  @moduledoc """
  Module to provide statistics for the Pbkdf2 password hashing function.
  """

  alias Pbkdf2.Base64

  @doc """
  Hash a password with Pbkdf2 and print out a report.

  This function hashes the password and salt with Pbkdf2.Base.hash_password/3
  and prints out statistics which can help you choose how many rounds to use
  with Pbkdf2.
  """
  def report(password, salt, opts \\ []) do
    {exec_time, encoded} = :timer.tc(Pbkdf2.Base, :hash_password, [password, salt, opts])
    Pbkdf2.verify_hash(encoded, password)
    |> format_result(encoded, exec_time)
  end

  defp format_result(check, encoded, exec_time) do
    [_, alg, rounds, _, hash] = String.split(encoded, "$")
    IO.puts """
    Digest: #{alg}
    Digest length: #{Base64.decode(hash) |> byte_size}
    Rounds: #{rounds}
    #{format_time(exec_time)} seconds
    Verification #{if check, do: "ok", else: "failed"}
    """
  end

  defp format_time(time) do
    Float.round(time / 1_000_000, 2)
  end
end
