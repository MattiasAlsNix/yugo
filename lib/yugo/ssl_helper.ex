defmodule Yugo.SSLHelper do
  @moduledoc """
  Helper functions for SSL/TLS connections.
  """

  # List of used OIDs for SSL/TLS certificates: https://www.alvestrand.no/objectid/2.5.29.html
  @id_ce_subject_alt_name {2, 5, 29, 17}

  @doc ~S"""

  ## Examples:

      iex> opts = Yugo.SSLHelper.ssl_opts(~c"mail.example.com", :verify_peer)
      iex> assert true == Keyword.has_key?(opts, :verify_fun)

  """
  @spec ssl_opts(charlist(), :verify_none | :verify_peer) :: [any]
  def ssl_opts(server, ssl_verify) do
    opts = [
      server_name_indication: server,
      verify: ssl_verify,
      cacerts: :public_key.cacerts_get()
    ]

    if :verify_peer == ssl_verify do
      opts ++ [verify_fun: {&Yugo.SSLHelper.wildcard_verify_fun/3, [hostname: server]}]
    else
      opts
    end
  end

  @spec use_socket(Yugo.Conn.t(), Map.t()) :: {:ok, :ssl.sslsocket()} | {:error, any}
  def use_socket(
        %Yugo.Conn{socket: socket, server: server, ssl_verify: ssl_verify},
        common_connect_opts
      )
      when nil != socket do
    :ssl.connect(
      socket,
      ssl_opts(server, ssl_verify) ++ common_connect_opts,
      :infinity
    )
  end

  @spec connect(charlist(), integer, :verify_none | :verify_peer, Map.t()) ::
          {:ok, :ssl.sslsocket()} | {:error, any}
  def connect(server, port, ssl_verify, common_connect_opts) do
    :ssl.connect(
      server,
      port,
      ssl_opts(server, ssl_verify) ++ common_connect_opts
    )
  end

  @doc ~S"""
  Verify function for SSL/TLS connections.

  ## Examples:

      iex> Yugo.SSLHelper.wildcard_verify_fun([], {:bad_cert, :hostname_check_failed}, [hostname: ~c"mail.example.com", names: [~c"example.com", ~c"*.example.com"]])
      {:valid_peer, []}

      iex> Yugo.SSLHelper.wildcard_verify_fun([], {:bad_cert, :hostname_check_failed}, [hostname: ~c"mail.example.com", names: [~c"example.net", ~c"*.example.net"]])
      {:fail, {:bad_cert, :hostname_check_failed}}

      iex> Yugo.SSLHelper.wildcard_verify_fun([], {:bad_cert, :hostname_check_failed}, [])
      {:fail, []}

      iex> Yugo.SSLHelper.wildcard_verify_fun([], {:extension, {:Extension, {2, 5, 29, 17}, true, [dNSName: ~c"example.com", dNSName: ~c"*.example.com"]}}, [])
      {:valid, [names: [~c"example.com", ~c"*.example.com"]]}

      iex> Yugo.SSLHelper.wildcard_verify_fun([], {:extension, {:Extension, {2, 5, 29, 19}, true, []}}, [])
      {:unknown, []}

      iex> Yugo.SSLHelper.wildcard_verify_fun([], {:other, :event}, [])
      {{:other, :event}, []}

  """
  def wildcard_verify_fun(_part, {:bad_cert, :hostname_check_failed} = event, state) do
    # IO.puts("Hostname check failed: #{inspect(event)}")
    case state do
      [hostname: server, names: names] ->
        case valid_wildcard_available?(server, names) do
          false ->
            {:fail, event}

          true ->
            {:valid_peer, []}
        end

      _ ->
        {:fail, []}
    end
  end

  def wildcard_verify_fun(_part, {:bad_cert, _} = event, _state) do
    {:fail, event}
  end

  def wildcard_verify_fun(_part, {:extension, extension}, state) do
    case extension do
      {:Extension, @id_ce_subject_alt_name, _critical, names} ->
        extract_name = fn x ->
          {:dNSName, name} = x
          name
        end

        {:valid, state ++ [names: names |> Enum.map(extract_name)]}

      _ ->
        {:unknown, state}
    end
  end

  def wildcard_verify_fun(_part, event, state) do
    IO.puts("Unknown event: #{inspect(event)}")
    {event, state}
  end

  @doc ~S"""
  Check if a wildcard is available in the certificate names.

  ## Examples:

      iex> Yugo.SSLHelper.valid_wildcard_available?(~c"mail.example.com", [~c"example.com", ~c"*.example.com"])
      true

      iex> Yugo.SSLHelper.valid_wildcard_available?(~c"mail.example.com", [~c"example.net", ~c"*.example.net"])
      false

      iex> Yugo.SSLHelper.valid_wildcard_available?(~c"mail.example.com", [~c"example.com", ~c"example.net"])
      false
  """
  def valid_wildcard_available?(server, names) do
    case Enum.find(names, fn name -> String.contains?(to_string(name), "*") end) do
      nil -> false
      first_wildcard -> matches_wildcard?(server, to_string(first_wildcard))
    end
  end

  @doc """
  Check if a server matches a wildcard.

  Examples:

      iex> Yugo.SSLHelper.matches_wildcard?(~c"mail.example.com", ~c"*.example.com")
      true

      iex> Yugo.SSLHelper.matches_wildcard?(~c"bad.mail.example.com", ~c"*.example.net")
      false
  """
  def matches_wildcard?(server, wildcard) do
    to_string(server)
    # split server into parts
    |> String.split(".")
    # zip wildcard with server parts
    |> Enum.zip(to_string(wildcard) |> String.split("."))
    # check if all parts match
    |> Enum.all?(fn {s, w} -> s == w or "*" == w end)
  end
end
