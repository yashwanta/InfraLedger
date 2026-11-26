package app

import (
	"io/fs"
	"sort"
	"strings"

	"infraledger/docs"
)

// GuideOrganization is the organization that holds the built-in user guide.
const GuideOrganization = "InfraLedger Help"

type guideArticle struct{ Title, Content string }

func guideArticles() []guideArticle {
	files, e := fs.Glob(docs.KB, "kb/*.md")
	must(e)
	sort.Strings(files)
	out := make([]guideArticle, 0, len(files))
	for _, name := range files {
		data, e := fs.ReadFile(docs.KB, name)
		must(e)
		content := strings.ReplaceAll(string(data), "\r\n", "\n")
		first, _, _ := strings.Cut(content, "\n")
		title := strings.TrimSpace(strings.TrimPrefix(first, "# "))
		if title == "" || !strings.HasPrefix(first, "# ") {
			panic("user guide file " + name + " must start with a '# Title' line")
		}
		out = append(out, guideArticle{Title: title, Content: strings.TrimSpace(content)})
	}
	return out
}

// installGuide adds the user guide to the knowledge base, creating the help
// organization if needed. Existing guide articles are updated (as a new
// version) only when their content changed, so the call is safe to repeat.
func (a *App) installGuide(u M) (created, updated int) {
	var orgID string
	for _, r := range a.q("SELECT * FROM records WHERE type='organizations' AND deleted IS NULL") {
		if S(decode(S(r, "data")), "name") == GuideOrganization {
			orgID = S(r, "id")
			break
		}
	}
	if orgID == "" {
		org := a.insert(u, "organizations", M{"name": GuideOrganization, "status": "Active", "industry": "Documentation",
			"notes": "Built-in user guide for every InfraLedger page. Settings → Install / update user guide refreshes it."})
		orgID = S(org, "id")
	}
	existing := map[string]M{}
	for _, r := range a.q("SELECT * FROM records WHERE type='articles' AND org_id=? AND deleted IS NULL", orgID) {
		existing[S(decode(S(r, "data")), "name")] = r
	}
	for _, g := range guideArticles() {
		if r, ok := existing[g.Title]; ok {
			data := decode(S(r, "data"))
			if S(data, "content") == g.Content {
				continue
			}
			data["content"] = g.Content
			data["version"] = r["version"]
			a.update(u, r, data)
			updated++
			continue
		}
		a.insert(u, "articles", M{"name": g.Title, "orgId": orgID, "category": "User guide", "status": "Published",
			"owner": "InfraLedger", "visibility": "internal", "content": g.Content})
		created++
	}
	return created, updated
}
