// Package docs embeds the InfraLedger user guide so the server can install it
// into a workspace's knowledge base.
package docs

import "embed"

// KB holds one Markdown guide per application page. Each file starts with a
// "# Title" line that becomes the article name.
//
//go:embed kb/*.md
var KB embed.FS
