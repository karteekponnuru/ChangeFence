import json
from changefence.descriptors import build_descriptor_context, summarize_descriptor


def test_openapi_descriptor_extracts_security_relevant_operations(tmp_path):
    p = tmp_path / "finance-openapi.json"
    p.write_text(json.dumps({
        "openapi":"3.1.0",
        "info":{"title":"Finance API"},
        "paths":{
            "/payments/{id}/execute":{"post":{"operationId":"executePayment","summary":"Execute an approved payment","description":"Moves funds for the approved invoice."}},
            "/health":{"get":{"operationId":"health"}},
        },
    }))
    out = summarize_descriptor(p)
    assert out["type"] == "openapi"
    assert out["operations"][0]["operation_id"] == "executePayment"
    assert out["operations"][0]["path"] == "/payments/{id}/execute"


def test_mcp_descriptor_extracts_tool_names_and_descriptions(tmp_path):
    p = tmp_path / "tools.json"
    p.write_text(json.dumps({"tools":[{"name":"process_payment","description":"Execute a supplier payment","inputSchema":{"type":"object"}}]}))
    context = build_descriptor_context([str(p)])
    assert "mcp_tools" in context
    assert "process_payment" in context
    assert "Execute a supplier payment" in context
