defmodule Yugo.BadSSLTest do
  use ExUnit.Case, async: false

  @moduletag external: true

  @default_connection_opts [
    :binary,
    active: false,
    packet: 0,
    exit_on_close: true
  ]

  describe "BadSSL.com tests" do

    test "connect to www.badssl.com having valid certificate" do
      {:ok, socket} =
        Yugo.SSLHelper.connect(~c"www.badssl.com", 443, :verify_peer, @default_connection_opts)

      :ok = :ssl.close(socket)
    end

    test "connect to expired.badssl.com" do
      {:error, {:tls_alert, {:certificate_expired, reason}}} =
        Yugo.SSLHelper.connect(~c"expired.badssl.com", 443, :verify_peer, @default_connection_opts)

      assert_reason_contains(reason, "CLIENT ALERT: Fatal - Certificate Expired")
    end

    test "connect to wrong.host.badssl.com" do
      {:error, {:tls_alert, {:handshake_failure, reason}}} =
        Yugo.SSLHelper.connect(~c"wrong.host.badssl.com", 443, :verify_peer, @default_connection_opts)

      assert_reason_contains(reason, "CLIENT ALERT: Fatal - Handshake Failure")
    end

    test "connect to self-signed.badssl.com" do
      {:error, {:tls_alert, {:bad_certificate, reason}}} =
        Yugo.SSLHelper.connect(~c"self-signed.badssl.com", 443, :verify_peer, @default_connection_opts)

      assert_reason_contains(reason, "CLIENT ALERT: Fatal - Bad Certificate")
    end

    test "connect to untrusted-root.badssl.com" do
      {:error, {:tls_alert, {:unknown_ca, reason}}} =
        Yugo.SSLHelper.connect(~c"untrusted-root.badssl.com", 443, :verify_peer, @default_connection_opts)

      assert_reason_contains(reason, "CLIENT ALERT: Fatal - Unknown CA")
    end

    @tag :skip
    test "connect to revoked.badssl.com" do
      {:error, {:tls_alert, {:certificate_revoked, reason}}} =
        Yugo.SSLHelper.connect(~c"revoked.badssl.com", 443, :verify_peer, @default_connection_opts)

      assert_reason_contains(reason, "CLIENT ALERT: Fatal - Certificate Revoked")
    end

    @tag :skip
    test "connect to pinning-test.badssl.com" do
      {:error, {:tls_alert, {:unknown_ca, reason}}} =
        Yugo.SSLHelper.connect(~c"pinning-test.badssl.com", 443, :verify_peer, @default_connection_opts)

      assert_reason_contains(reason, "CLIENT ALERT: Fatal - Unknown CA")
    end
  end

  defp assert_reason_contains(reason, expected) do
    assert String.contains?(to_string(reason), expected)
  end
end
