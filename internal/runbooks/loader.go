package runbooks

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Loader produces a snapshot of all runbooks in the knowledge base.
// Implementations should be cheap to call repeatedly — the store will invoke
// Load on a periodic timer to pick up edits without restart.
type Loader interface {
	// Load returns all runbooks parsed from the source. Implementations
	// should return a partial result alongside an error when some files
	// failed to parse but others succeeded — the store will use the partial
	// result and log the error rather than discarding everything.
	Load(ctx context.Context) ([]*Runbook, error)
}

// frontmatter is the YAML schema we accept at the top of a runbook markdown
// file. All fields are optional; missing values are filled in from the
// filename / title heuristics.
type frontmatter struct {
	AlertNames []string `yaml:"alertnames"`
	Keywords   []string `yaml:"keywords"`
	Tags       []string `yaml:"tags"`
	Summary    string   `yaml:"summary"`
	Title      string   `yaml:"title"`
}

// fsLoader reads runbooks from a directory tree on the local filesystem.
// It walks the tree recursively and parses every .md file it finds.
type fsLoader struct {
	root string
}

// NewFSLoader creates a Loader that reads .md files recursively from the
// given root directory. The root must exist; nonexistent directories are
// reported as a Load error rather than silently returning an empty set so
// misconfigurations surface quickly.
func NewFSLoader(root string) Loader {
	return &fsLoader{root: root}
}

// Load walks the root directory and returns all parsed runbooks. Files that
// fail to parse are logged-via-error-aggregation but skipped — one bad
// runbook should not poison the rest of the KB.
func (l *fsLoader) Load(ctx context.Context) ([]*Runbook, error) {
	if l.root == "" {
		return nil, fmt.Errorf("fsLoader: root directory is empty")
	}
	info, err := os.Stat(l.root)
	if err != nil {
		return nil, fmt.Errorf("stat runbook root %q: %w", l.root, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("runbook root %q is not a directory", l.root)
	}

	var runbooks []*Runbook
	var parseErrs []string

	walkErr := filepath.WalkDir(l.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			return nil
		}
		if !strings.EqualFold(filepath.Ext(d.Name()), ".md") {
			return nil
		}

		rb, parseErr := parseRunbookFile(path, l.root)
		if parseErr != nil {
			parseErrs = append(parseErrs, fmt.Sprintf("%s: %v", path, parseErr))
			return nil
		}
		runbooks = append(runbooks, rb)
		return nil
	})

	if walkErr != nil {
		return runbooks, fmt.Errorf("walk runbook directory: %w", walkErr)
	}
	if len(parseErrs) > 0 {
		// Best-effort: return what parsed plus an aggregated error so the
		// caller can log the bad files but keep using the good ones.
		return runbooks, fmt.Errorf("some runbooks failed to parse: %s",
			strings.Join(parseErrs, "; "))
	}
	return runbooks, nil
}

// parseRunbookFile reads one markdown file, extracts optional YAML
// frontmatter, and returns a populated Runbook. Frontmatter is delimited by
// `---` lines at the very top of the file (the first non-empty line must be
// `---`).
func parseRunbookFile(path, root string) (*Runbook, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}

	fmText, body, err := splitFrontmatter(f)
	if err != nil {
		return nil, fmt.Errorf("split frontmatter: %w", err)
	}

	var fm frontmatter
	if fmText != "" {
		if err := yaml.Unmarshal([]byte(fmText), &fm); err != nil {
			return nil, fmt.Errorf("parse frontmatter: %w", err)
		}
	}

	id := relPath(root, path)
	rb := &Runbook{
		ID:         id,
		AlertNames: fm.AlertNames,
		Keywords:   fm.Keywords,
		Tags:       fm.Tags,
		Summary:    fm.Summary,
		Body:       body,
		UpdatedAt:  stat.ModTime(),
	}

	// Title resolution: explicit frontmatter > first H1 in body > filename stem.
	if fm.Title != "" {
		rb.Title = fm.Title
	} else if h1 := firstH1(body); h1 != "" {
		rb.Title = h1
	} else {
		rb.Title = filenameStem(path)
	}

	// AlertName fallback: filename stem (kebab-case → CamelCase variants are
	// matched case-insensitively at retrieval time, so we don't try to
	// normalize here).
	if len(rb.AlertNames) == 0 {
		stem := filenameStem(path)
		if stem != "" {
			rb.AlertNames = []string{stem}
		}
	}

	// Keyword fallback: pull simple alphanumeric tokens from the title.
	if len(rb.Keywords) == 0 {
		rb.Keywords = extractKeywords(rb.Title)
	}

	return rb, nil
}

// splitFrontmatter reads the file, returning (frontmatterYAML, body) when
// the file starts with `---\n...---\n`, or ("", entireFile) otherwise.
func splitFrontmatter(f *os.File) (string, string, error) {
	scanner := bufio.NewScanner(f)
	// Allow large lines (10MB) so big code blocks in runbooks don't break us.
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	var (
		first      = true
		inFM       = false
		fmLines    []string
		bodyLines  []string
		sawFMStart = false
		sawFMEnd   = false
	)

	for scanner.Scan() {
		line := scanner.Text()
		if first {
			first = false
			if strings.TrimSpace(line) == "---" {
				inFM = true
				sawFMStart = true
				continue
			}
			// No frontmatter — treat first line as body.
			bodyLines = append(bodyLines, line)
			continue
		}
		if inFM {
			if strings.TrimSpace(line) == "---" {
				inFM = false
				sawFMEnd = true
				continue
			}
			fmLines = append(fmLines, line)
			continue
		}
		bodyLines = append(bodyLines, line)
	}
	if err := scanner.Err(); err != nil {
		return "", "", err
	}

	// If we opened a frontmatter block but never saw `---` to close it,
	// treat the whole file as body — the file is malformed but we'd rather
	// surface it as "no metadata" than reject it.
	if sawFMStart && !sawFMEnd {
		return "", strings.Join(append([]string{"---"}, append(fmLines, bodyLines...)...), "\n"), nil
	}

	return strings.Join(fmLines, "\n"), strings.Join(bodyLines, "\n"), nil
}

// firstH1 returns the first markdown H1 heading text in body, stripping the
// "# " prefix and any trailing whitespace. Returns "" if no H1 is present.
func firstH1(body string) string {
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "# ") {
			return strings.TrimSpace(strings.TrimPrefix(trimmed, "# "))
		}
	}
	return ""
}

// filenameStem returns the file's basename without the .md extension.
func filenameStem(path string) string {
	base := filepath.Base(path)
	return strings.TrimSuffix(base, filepath.Ext(base))
}

// relPath returns path relative to root when possible, otherwise the
// absolute path. Used as the runbook ID so it's both stable and readable.
func relPath(root, path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return abs
	}
	if rel, err := filepath.Rel(rootAbs, abs); err == nil {
		return rel
	}
	return abs
}

// extractKeywords pulls lowercased word tokens from text, dropping very
// short tokens (< 3 chars) and a tiny stoplist. This is a fallback used
// only when frontmatter doesn't supply explicit keywords.
func extractKeywords(text string) []string {
	stop := map[string]bool{
		"the": true, "and": true, "for": true, "with": true, "from": true,
		"this": true, "that": true, "into": true, "your": true, "you": true,
		"are": true, "but": true, "not": true, "any": true, "all": true,
		"how": true, "why": true, "what": true, "when": true, "where": true,
	}
	seen := map[string]bool{}
	var out []string

	var b strings.Builder
	flush := func() {
		if b.Len() == 0 {
			return
		}
		w := strings.ToLower(b.String())
		b.Reset()
		if len(w) < 3 || stop[w] {
			return
		}
		if seen[w] {
			return
		}
		seen[w] = true
		out = append(out, w)
	}
	for _, r := range text {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			flush()
		}
	}
	flush()
	return out
}
