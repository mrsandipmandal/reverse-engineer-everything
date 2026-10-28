// Package mcp exposes the versioned REE MCP surface.
package mcp

import (
	"context"
	"fmt"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/setup"
	"github.com/mrsandipmandal/reverse-engineer-everything/internal/version"
)

const (
	// ServerName is the machine-readable MCP server name.
	ServerName = "ree"
	// SurfaceVersion versions the REE-native MCP contract.
	SurfaceVersion = "0.2"
	// VersionToolName is the build identity tool.
	VersionToolName = "ree_version"
	// DoctorToolName is the environment diagnostics tool.
	DoctorToolName = "ree_doctor"
)

type doctorFunc func(context.Context) setup.Report

// NewServer creates the REE MCP server for the given build identity.
func NewServer(info version.Info) *sdk.Server {
	return newServer(info, setup.DiagnoseDefault)
}

// Run serves the REE MCP server over stdio.
func Run(ctx context.Context, info version.Info) error {
	return NewServer(info).Run(ctx, &sdk.StdioTransport{})
}

func newServer(info version.Info, diagnose doctorFunc) *sdk.Server {
	server := sdk.NewServer(
		&sdk.Implementation{
			Name:       ServerName,
			Title:      version.DisplayName,
			Version:    info.Version,
			WebsiteURL: "https://github.com/mrsandipmandal/reverse-engineer-everything",
		},
		&sdk.ServerOptions{
			Instructions: fmt.Sprintf(
				"REE MCP surface %s. This server exposes build identity, local environment diagnostics, and read-only analysis of one local ELF or PE artifact. ree_analyze returns a path-free summary and optionally the sealed evidence record; it never executes, modifies, or uploads an artifact.",
				SurfaceVersion,
			),
		},
	)

	sdk.AddTool(server, &sdk.Tool{
		Name:        VersionToolName,
		Title:       "REE version",
		Description: "Return the REE build identity for this server.",
		Annotations: readOnlyAnnotations("REE version"),
	}, func(context.Context, *sdk.CallToolRequest, struct{}) (*sdk.CallToolResult, version.Info, error) {
		return nil, info, nil
	})

	sdk.AddTool(server, &sdk.Tool{
		Name:        DoctorToolName,
		Title:       "REE doctor",
		Description: "Report local development and release tool availability. This tool does not analyze artifacts.",
		Annotations: readOnlyAnnotations("REE doctor"),
	}, func(ctx context.Context, _ *sdk.CallToolRequest, _ struct{}) (*sdk.CallToolResult, setup.Report, error) {
		return nil, diagnose(ctx), nil
	})

	sdk.AddTool(server, &sdk.Tool{
		Name:        AnalyzeToolName,
		Title:       "REE analyze",
		Description: "Analyze one local ELF or PE artifact and return its path-free summary and optional sealed evidence. This tool reads the file and never executes or modifies it.",
		Annotations: readOnlyAnnotations("REE analyze"),
	}, func(ctx context.Context, _ *sdk.CallToolRequest, in analyzeInput) (*sdk.CallToolResult, analyzeReport, error) {
		report, err := analyzeArtifact(ctx, in, info.Version)
		if err != nil {
			return nil, analyzeReport{}, err
		}
		return nil, report, nil
	})

	return server
}

func readOnlyAnnotations(title string) *sdk.ToolAnnotations {
	closedWorld := false
	return &sdk.ToolAnnotations{
		Title:          title,
		ReadOnlyHint:   true,
		IdempotentHint: true,
		OpenWorldHint:  &closedWorld,
	}
}
