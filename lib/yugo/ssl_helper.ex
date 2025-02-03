defmodule Yugo.SSLHelper do
  @moduledoc """
  Helper functions for SSL/TLS connections.
  """

  @spec ssl_opts(String.t(), :verify_none | :verify_peer) :: [any]
  defp ssl_opts(server, ssl_verify) do
         [
           server_name_indication: server,
           verify: ssl_verify,
           cacerts: :public_key.cacerts_get()
         ]
  end

  @spec use_socket(Yugo.Conn.t(), Map.t()) :: {:ok, :ssl.sslsocket()} | {:error, any}
  def use_socket(%Yugo.Conn{socket: socket, server: server, ssl_verify: ssl_verify}, common_connect_opts) when nil != socket do
    :ssl.connect(
      socket,
      ssl_opts(server, ssl_verify) ++ common_connect_opts,
      :infinity
    )
  end

  @spec connect(String.t(), integer, :verify_none | :verify_peer, Map.t()) :: {:ok, :ssl.sslsocket()} | {:error, any}
  def connect(server, port, ssl_verify, common_connect_opts) do
    :ssl.connect(
      server,
      port,
      ssl_opts(server, ssl_verify) ++ common_connect_opts
    )
  end
end