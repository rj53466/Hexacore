# tools/ — capability modules + MCP servers (not yet built)

Phase 1+ (Epic C). Each capability = {typed input schema, action_class, sandboxed runner,
output parser → JSON, MCP wrapper, unit tests}. **No capability may run without going through
`api/hexacore/safety`.** See `Brain/08-TOOL-INTEGRATION.md` for the adapter contract.
