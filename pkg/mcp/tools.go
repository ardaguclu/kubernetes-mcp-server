package mcp

import "github.com/modelcontextprotocol/go-sdk/mcp"

type ToolWithHandler struct {
	Tool    *mcp.Tool
	Handler mcp.ToolHandler
}
