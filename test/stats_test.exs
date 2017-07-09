defmodule Pbkdf2.StatsTest do
  use ExUnit.Case

  import ExUnit.CaptureIO
  alias Pbkdf2.Stats

  test "print report with default options" do
    report = capture_io(fn -> Stats.report() end)
    assert report =~ "Digest: pbkdf2-sha512\n"
    assert report =~ "Digest length: 64\n"
    assert report =~ "Hash: $pbkdf2-sha512$160000$"
    assert report =~ "Rounds: 160000\n"
    assert report =~ "Verification ok"
  end

  test "print report with pbkdf2_sha256" do
    report = capture_io(fn -> Stats.report([digest: :sha256]) end)
    assert report =~ "Digest: pbkdf2-sha256\n"
    assert report =~ "Digest length: 32\n"
    assert report =~ "Hash: $pbkdf2-sha256$160000$"
    assert report =~ "Rounds: 160000\n"
    assert report =~ "Verification ok"
  end

  test "use custom options" do
    report = capture_io(fn -> Stats.report([rounds: 300_000]) end)
    assert report =~ "Digest: pbkdf2-sha512\n"
    assert report =~ "Digest length: 64\n"
    assert report =~ "Hash: $pbkdf2-sha512$300000$"
    assert report =~ "Rounds: 300000\n"
    assert report =~ "Verification ok"
  end

end
