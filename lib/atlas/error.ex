defmodule Atlas.Error do
  @moduledoc """
  A failed Backend API call: an HTTP error response (`:status` set, `:code` the
  Atlas error code such as `"INSUFFICIENT_SCOPE"`) or a transport failure
  (`:status` is `nil`, `:code` is `"TRANSPORT_ERROR"`). Also raised by the
  `stream_*` functions.
  """
  defexception [:status, :code, :message, :required_scope, :docs_url, :request_id, :body]

  @type t :: %__MODULE__{}

  @doc false
  def from_response(status, body, headers) do
    parsed = AtlasAuth.Errors.parse(body) || %{}

    %__MODULE__{
      status: status,
      code: parsed[:code] || "HTTP_#{status}",
      message: parsed[:message] || "Atlas API returned HTTP #{status}",
      required_scope: parsed[:required_scope],
      docs_url: parsed[:docs_url],
      request_id: header(headers, "x-request-id"),
      body: body
    }
  end

  @doc false
  def transport(reason),
    do: %__MODULE__{code: "TRANSPORT_ERROR", message: "request failed: " <> Exception.message(reason_exception(reason)), body: nil}

  defp reason_exception(%{__exception__: true} = e), do: e
  defp reason_exception(other), do: %RuntimeError{message: inspect(other)}

  defp header(headers, name) do
    case Req.Response.get_header(%Req.Response{headers: headers}, name) do
      [v | _] -> v
      _ -> nil
    end
  end
end
