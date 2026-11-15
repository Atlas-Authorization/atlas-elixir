defmodule Atlas.DoctorTest do
  use ExUnit.Case, async: false

  defp client(routes, key \\ "sk_test_abc") do
    stub = :"doctor_#{System.unique_integer([:positive])}"

    Req.Test.stub(stub, fn conn ->
      {status, headers, body} = Map.fetch!(routes, conn.request_path)
      conn = Enum.reduce(headers, conn, fn {k, v}, c -> Plug.Conn.put_resp_header(c, k, v) end)
      conn |> Plug.Conn.put_resp_content_type("application/json") |> Plug.Conn.send_resp(status, Jason.encode!(body))
    end)

    Atlas.new(key, req_options: [plug: {Req.Test, stub}, retry: false], base_url: "https://api.atlas.example")
  end

  defp now_header, do: [{"date", to_string(:httpd_util.rfc1123_date())}]
  defp by_name(report, name), do: Enum.find(report.checks, &(&1.name == name))
  defp jwks_ok, do: fn _ -> {:ok, [%{"kid" => "k1"}]} end

  test "a healthy setup passes every check" do
    c = client(%{"/v1/status" => {200, now_header(), %{"status" => "operational"}}, "/v1/instance" => {200, [], %{"id" => "ins_1"}}})
    report = Atlas.Doctor.run(c, issuer: "https://inst.example", fetcher: jwks_ok())
    assert report.ok?
    assert Enum.all?(report.checks, &(&1.status == :pass))
    assert Atlas.Doctor.format(report) =~ "All checks passed."
  end

  test "a skewed clock, a rejected key and a missing JWKS are reported" do
    old = [{"date", "Mon, 01 Jan 2024 00:00:00 GMT"}]
    c = client(%{"/v1/status" => {200, old, %{"status" => "degraded"}}, "/v1/instance" => {401, [], %{"errors" => [%{"code" => "UNAUTHORIZED"}]}}})
    report = Atlas.Doctor.run(c, jwks_url: "https://inst.example/.well-known/jwks.json", fetcher: fn _ -> {:error, :nxdomain} end)
    refute report.ok?
    assert by_name(report, :clock).status == :fail
    assert by_name(report, :api).status == :warn
    assert by_name(report, :instance).status == :fail
    assert by_name(report, :jwks).status == :fail
  end

  test "a publishable key and an insecure base URL fail; no issuer means the JWKS is not checked" do
    c = client(%{"/v1/status" => {200, now_header(), %{"status" => "operational"}}, "/v1/instance" => {200, [], %{}}}, "pk_test_abc")
    report = Atlas.Doctor.run(c)
    assert by_name(report, :key).status == :fail
    assert by_name(report, :jwks).status == :warn
    insecure = %{c | base_url: "http://api.atlas.example"}
    assert by_name(Atlas.Doctor.run(insecure), :config).status == :fail
  end
end
