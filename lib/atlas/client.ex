defmodule Atlas.Client do
  @moduledoc """
  The HTTP core behind every `Atlas.<Resource>` module (built on `Req`).

  Options for `new/2`: `:base_url` (default `https://api.atlasauth.net`) and
  `:req_options` (merged into every `Req` request, for example `retry: false`
  or `plug: {Req.Test, MyStub}` in tests).
  """

  defstruct [:secret_key, :base_url, req_options: []]

  @type t :: %__MODULE__{}
  @default_base "https://api.atlasauth.net"

  @doc "Build a client from a secret key (`sk_...`)."
  @spec new(String.t(), keyword()) :: t()
  def new(secret_key, opts \\ []) when is_binary(secret_key) and secret_key != "" do
    %__MODULE__{
      secret_key: secret_key,
      base_url: String.trim_trailing(Keyword.get(opts, :base_url, @default_base), "/"),
      req_options: Keyword.get(opts, :req_options, [])
    }
  end

  @doc false
  @spec request(t(), atom(), String.t(), map(), term(), keyword()) :: {:ok, term()} | {:error, Atlas.Error.t()}
  def request(%__MODULE__{} = c, method, template, bindings, body, opts) do
    headers =
      [{"authorization", "Bearer " <> c.secret_key}, {"accept", "application/json"}] ++
        idem(opts[:idempotency_key]) ++ Enum.map(opts[:headers] || [], fn {k, v} -> {to_string(k), to_string(v)} end)

    req =
      Keyword.merge(
        [method: method, url: c.base_url <> expand(template, bindings), headers: headers, decode_body: false, params: opts[:params] || []],
        c.req_options
      )
      |> put_body(body, opts[:content_type])

    case Req.request(req) do
      {:ok, %Req.Response{status: s} = r} when s in 200..299 -> {:ok, decode(r)}
      {:ok, %Req.Response{status: s} = r} -> {:error, Atlas.Error.from_response(s, decode(r), r.headers)}
      {:error, reason} -> {:error, Atlas.Error.transport(reason)}
    end
  end

  @doc false
  # Pages through a cursor list: follows `next_cursor`, else the last item id while `has_more`.
  def stream(%__MODULE__{} = c, template, bindings, opts) do
    Stream.resource(
      fn -> {:more, nil} end,
      fn
        :done ->
          {:halt, :done}

        {:more, cursor} ->
          params = (opts[:params] || []) |> Enum.to_list() |> Keyword.new(fn {k, v} -> {to_atom(k), v} end)
          params = if cursor, do: Keyword.put(params, :starting_after, cursor), else: params

          case request(c, :get, template, bindings, nil, Keyword.put(opts, :params, params)) do
            {:ok, %{"data" => items} = page} when is_list(items) -> {items, next(page, items)}
            {:ok, items} when is_list(items) -> {items, :done}
            {:ok, _} -> {[], :done}
            {:error, err} -> raise err
          end
      end,
      fn _ -> :ok end
    )
  end

  defp to_atom(k) when is_atom(k), do: k
  defp to_atom(k), do: String.to_atom(k)

  defp next(%{"has_more" => true} = page, items) do
    case page["next_cursor"] || last_id(items) do
      nil -> :done
      cursor -> {:more, cursor}
    end
  end

  defp next(%{"next_cursor" => c}, _) when is_binary(c) and c != "", do: {:more, c}
  defp next(_, _), do: :done

  defp last_id([]), do: nil
  defp last_id(items), do: with(%{"id" => id} <- List.last(items), do: id)

  defp idem(nil), do: []
  defp idem(key), do: [{"idempotency-key", key}]

  defp put_body(req, nil, _), do: req
  defp put_body(req, body, nil) when is_map(body) or is_list(body), do: Keyword.put(req, :json, body)

  defp put_body(req, body, type) when is_binary(body),
    do: req |> Keyword.put(:body, body) |> Keyword.update!(:headers, &[{"content-type", type || "application/octet-stream"} | &1])

  # Path values are percent-encoded so an id can never add a path segment.
  defp expand(template, bindings) do
    Regex.replace(~r/\{(\w+)\}/, template, fn _, name ->
      URI.encode(to_string(Map.fetch!(bindings, name)), &URI.char_unreserved?/1)
    end)
  end

  defp decode(%Req.Response{body: ""}), do: nil

  defp decode(%Req.Response{body: body} = r) do
    json? = r |> Req.Response.get_header("content-type") |> Enum.any?(&(&1 =~ "json" and not (&1 =~ "x-ndjson")))
    if json?, do: (case Jason.decode(body) do {:ok, v} -> v; _ -> body end), else: body
  end
end
