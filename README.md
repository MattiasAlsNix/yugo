# Yugo - Fork

**Important**:

I use this project as a playground to learn Elixir and implement some features I need for my personal projects.
Please do not use this fork for any purpose other than learning or testing or having fun with my code.

## Testing with different TLS certificates
I am using the site [https://www.badssl.com](https://www.badssl.com) to test the TLS certificate validation.
The site provides different endpoints with different issues in the certificate chain.

To test the certificate validation, I have added a test case that uses the endpoint `https://bad.host.badssl.com/` which uses a not matching wildcard certificate.

```shell
$ mix test --only external
Running ExUnit with seed: 625074, max_cases: 20
Excluding tags: [:test]
Including tags: [:external]
[...]
```


---

Yugo is an easy and high-level IMAP client library for Elixir.


To begin, start a `Yugo.Client` as part of your application's supervision tree:
```elixir
defmodule MyApp.Application do
  use Application

  @impl true
  def start(_type, _args) do
    children = [
      {Yugo.Client,
       name: :example_client,
       server: "imap.example.com",
       username: "me@example.com",
       password: "pa55w0rd"}
    ]

    Supervisor.start_link(children, strategy: :one_for_one)
  end
end
```

Now you can call `Yugo.subscribe/2` to have your process receive messages whenever a new email arrives that matches the provided `Yugo.Filter`:

```elixir
# filter to only notify us about messages containing "hello" or "goodbye" in the subject:
my_filter =
  Yugo.Filter.all()
  |> Yugo.Filter.subject_matches(~r/(hello|goodbye)/)

# By subscribing, our process will be notified about all future emails that match the filter.
Yugo.subscribe(:example_client, my_filter)

receive do
  {:email, _client, message} ->
    IO.puts("Received an email with subject `#{message.subject}`:")
    IO.inspect(message)
end
```
