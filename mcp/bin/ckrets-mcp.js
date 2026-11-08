#!/usr/bin/env node
'use strict';
// ckrets-mcp: the stdio MCP server (lib/server.js). Logs nothing to stdout but JSON-RPC.
require('../lib/server').serveStdio();
