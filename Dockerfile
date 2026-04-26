# Minimal image for running depguard as an MCP server over stdio.
# Used by directories like Glama to verify the server responds to MCP introspection.
#
# Build:  docker build -t depguard .
# Run:    docker run --rm -i depguard
FROM node:22-alpine

# Install the latest published version from npm
RUN npm install -g depguard-cli@latest

# Drop privileges
USER node

# Speak MCP over stdio (the only supported transport)
ENTRYPOINT ["depguard-cli", "--mcp"]
