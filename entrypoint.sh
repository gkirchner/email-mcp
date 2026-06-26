#!/bin/sh
if [ -n "$EMAIL_MCP_CONFIG" ]; then
  mkdir -p /home/node/.config/email-mcp
  printf '%s' "$EMAIL_MCP_CONFIG" > /home/node/.config/email-mcp/config.toml
fi
exec node dist/main.js "$@"