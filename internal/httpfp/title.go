package httpfp

import (
	"bytes"
	"html"
	"regexp"
	"strings"
)

var (
	titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	spaceRe = regexp.MustCompile(`\s+`)
)

// ExtractTitle returns the unescaped, whitespace-collapsed <title> text,
// sanitised to valid UTF-8 without control characters and cut to 512 runes.
// The text is returned as is (not HTML-safe): consumers must escape it.
func ExtractTitle(body []byte) string {
	m := titleRe.FindSubmatch(body)
	if m == nil {
		return ""
	}
	raw := m[1]
	if len(raw) > maxTitleRunes*16 {
		raw = raw[:maxTitleRunes*16] // bound the work, 512 runes fit easily
	}
	t := strings.ToValidUTF8(string(raw), "�")
	t = html.UnescapeString(t)
	t = spaceRe.ReplaceAllString(t, " ")
	t = clean(t, len(t))
	t = strings.TrimSpace(t)
	if r := []rune(t); len(r) > maxTitleRunes {
		t = string(r[:maxTitleRunes])
	}
	return t
}

var (
	linkTagRe = regexp.MustCompile(`(?is)<link\b[^>]*>`)
	relRe     = regexp.MustCompile(`(?is)\brel\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
	hrefRe    = regexp.MustCompile(`(?is)\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
)

func attr(re *regexp.Regexp, tag string) string {
	m := re.FindStringSubmatch(tag)
	if m == nil {
		return ""
	}
	for _, g := range m[1:] {
		if g != "" {
			return html.UnescapeString(g)
		}
	}
	return ""
}

// FaviconLinks returns the href values of <link rel="...icon..."> tags.
func FaviconLinks(body []byte) []string {
	var out []string
	for _, tag := range linkTagRe.FindAllString(string(body), 20) {
		rel := strings.ToLower(attr(relRe, tag))
		if !strings.Contains(rel, "icon") || strings.Contains(rel, "mask-icon") {
			continue
		}
		if h := attr(hrefRe, tag); h != "" && !strings.HasPrefix(strings.ToLower(h), "data:") {
			out = append(out, h)
		}
	}
	return out
}

func looksLikeHTML(ct string, body []byte) bool {
	if strings.HasPrefix(strings.ToLower(ct), "text/html") {
		return true
	}
	head := bytes.ToLower(bytes.TrimSpace(body[:min(len(body), 64)]))
	return bytes.HasPrefix(head, []byte("<!doctype html")) || bytes.HasPrefix(head, []byte("<html"))
}
