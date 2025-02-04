defmodule Yugo.SSLHelper do
  @moduledoc """
  Helper functions for SSL/TLS connections.
  """

  # List of used OIDs for SSL/TLS certificates: https://www.alvestrand.no/objectid/2.5.29.html
  @id_ce_subject_alt_name {2, 5, 29, 17}

  @spec ssl_opts(charlist(), :verify_none | :verify_peer) :: [any]
  defp ssl_opts(server, ssl_verify) do
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

  def wildcard_verify_fun(_part, event = {:bad_cert, :hostname_check_failed}, state) do
    IO.puts("Bad certificate: hostname_check_failed")

    case state do
      [hostname: server, names: names] ->
        IO.puts("Checking for wildcards in Certificate names: #{inspect(names)}")

        case valid_wildcard_available?(server, names) do
          false ->
            IO.puts("No valid wildcard found in certificate names")
            event

          true ->
            IO.puts("Valid wildcard found in certificate names")
            {:valid, []}
        end

      _ ->
        {:invalid, state}
    end
  end

  def wildcard_verify_fun(_part, {:extension, extension}, state) do
    case extension do
      {:Extension, @id_ce_subject_alt_name, critical, names} ->
       IO.puts("Extension names (critical: #{critical}): #{inspect(names)}")

        extract_name = fn x ->
          {:dNSName, name} = x
          name
        end

        {:valid, state ++ [names: names |> Enum.map(extract_name)]}

      _ ->
        {:valid, state}
    end
  end

  def wildcard_verify_fun(_part, event, state) do
    IO.puts("Default event handling: #{inspect(event)}")
    {event, state}
  end

  @doc """
  Check if a wildcard is available in the certificate names.

  Examples:

      iex> Yugo.SSLHelper.valid_wildcard_available?(~c"mail.example.com", [~c"example.com", ~c"*.example.com"])
      true

      iex> Yugo.SSLHelper.valid_wildcard_available?(~c"mail.example.com", [~c"example.net", ~c"*.example.net"])
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
