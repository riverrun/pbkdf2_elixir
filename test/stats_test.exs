defmodule Pbkdf2.StatsTest do
  use ExUnit.Case

  import ExUnit.CaptureIO
  alias Pbkdf2.Stats

  test "print report with default options" do
    report = capture_io(fn -> Stats.report() end)
    assert report =~ "Digest:\t\tpbkdf2-sha512\n"
    assert report =~ "Digest length:\t64\n"
    assert report =~ "Hash:\t\t$pbkdf2-sha512$160000$"
    assert report =~ "Rounds:\t\t160000\n"
    assert report =~ "Verification OK"
  end

  test "print report with pbkdf2_sha256" do
    report = capture_io(fn -> Stats.report([digest: :sha256]) end)
    assert report =~ "Digest:\t\tpbkdf2-sha256\n"
    assert report =~ "Digest length:\t32\n"
    assert report =~ "Hash:\t\t$pbkdf2-sha256$160000$"
    assert report =~ "Rounds:\t\t160000\n"
    assert report =~ "Verification OK"
  end

  test "use custom options" do
    report = capture_io(fn -> Stats.report([rounds: 300_000]) end)
    assert report =~ "Digest:\t\tpbkdf2-sha512\n"
    assert report =~ "Digest length:\t64\n"
    assert report =~ "Hash:\t\t$pbkdf2-sha512$300000$"
    assert report =~ "Rounds:\t\t300000\n"
    assert report =~ "Verification OK"
  end

  test "print report with django format" do
    report = capture_io(fn -> Stats.report([format: :django]) end)
    assert report =~ "Digest length:\t64\n"
    assert report =~ "Hash:\t\tpbkdf2_sha512$160000$"
    assert report =~ "Verification OK"
    report = capture_io(fn -> Stats.report([digest: :sha256, format: :django]) end)
    assert report =~ "Digest length:\t32\n"
    assert report =~ "Hash:\t\tpbkdf2_sha256$160000$"
    assert report =~ "Verification OK"
  end

end
