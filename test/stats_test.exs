defmodule Pbkdf2.StatsTest do
  use ExUnit.Case

  import ExUnit.CaptureIO
  alias Pbkdf2.Stats

  test "print report with default options" do
    report = capture_io(fn -> Stats.report("password", "somesaltsomesalt", []) end)
    assert report =~ "Digest: pbkdf2-sha512\n"
    assert report =~ "Digest length: 64\n"
    assert report =~ "Rounds: 160000\n"
    assert report =~ "Verification ok"
  end

  test "print report with pbkdf2_sha256" do
    report = capture_io(fn -> Stats.report("password", "somesaltsomesalt", [digest: :sha256]) end)
    assert report =~ "Digest: pbkdf2-sha256\n"
    assert report =~ "Digest length: 32\n"
    assert report =~ "Rounds: 160000\n"
    assert report =~ "Verification ok"
  end

  test "use custom options" do
    opts = [rounds: 300_000]
    report = capture_io(fn -> Stats.report("password", "somesaltsomesalt", opts) end)
    assert report =~ "Digest: pbkdf2-sha512\n"
    assert report =~ "Digest length: 64\n"
    assert report =~ "Rounds: 300000\n"
    assert report =~ "Verification ok"
  end

end
