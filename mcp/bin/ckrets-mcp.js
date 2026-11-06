#!/usr/bin/env node
'use strict';
// npx -y @ckrets/mcp@1: the stdio MCP server (lib/server.js). Logs nothing to stdout but JSON-RPC.
require('../lib/server').serveStdio();
