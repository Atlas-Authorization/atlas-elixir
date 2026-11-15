defmodule Atlas.HelpersTest do
  use ExUnit.Case, async: true

  defp client(test_pid) do
    stub = :"helpers_#{System.unique_integer([:positive])}"

    Req.Test.stub(stub, fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      send(test_pid, {:request, conn.method, conn.request_path, body})
      Req.Test.json(conn, %{"object" => "integration_events_secret", "secret" => "whsec_new"})
    end)

    Atlas.new("sk_test_x", req_options: [plug: {Req.Test, stub}, retry: false])
  end

  test "rotate_events_secret/4 posts the overlap and validates it" do
    c = client(self())
    assert {:ok, %{"secret" => "whsec_new"}} = Atlas.Helpers.rotate_events_secret(c, "forumulate", overlap_seconds: 3600)
    assert_received {:request, "POST", "/v1/instance/integrations/forumulate/events_secret/rotate", body}
    assert Jason.decode!(body) == %{"overlap_seconds" => 3600}

    assert {:error, {:invalid, _}} = Atlas.Helpers.rotate_events_secret(c, "forumulate", overlap_seconds: 604_801)
    assert {:ok, _} = Atlas.Helpers.rotate_events_secret(c, "forumulate")
    assert_received {:request, "POST", _, "{}"}
  end

  test "jwt_template_settings/1 validates lifetime, algorithm and secret" do
    assert {:ok, %{lifetime_seconds: 300, audience: "api", algorithm: "RS256"}} =
             Atlas.Helpers.jwt_template_settings(lifetime_seconds: 300, audience: "api", algorithm: "RS256")

    assert {:ok, %{lifetime_seconds: nil}} = Atlas.Helpers.jwt_template_settings(lifetime_seconds: nil)
    assert {:error, {:invalid, _}} = Atlas.Helpers.jwt_template_settings(lifetime_seconds: 5)
    assert {:error, {:invalid, _}} = Atlas.Helpers.jwt_template_settings(algorithm: "ES512")
    assert {:error, {:invalid, _}} = Atlas.Helpers.jwt_template_settings(signing_secret: "short", algorithm: "HS256")
    assert {:ok, _} = Atlas.Helpers.jwt_template_settings(signing_secret: String.duplicate("s", 16), algorithm: "HS256")
  end
end
