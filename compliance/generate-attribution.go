package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	texttpl "text/template"
	"time"

	spdxexp "github.com/khulnasoft/tunnel/pkg/licensing"
)

type Config struct {
	SBOMPath         string
	LicenseMapPath   string
	HTMLTemplatePath string
	NoticeTplPath    string

	OutDir           string
	OutLicensesDir   string
	CustomLicenseDir string

	SPDXVersion string

	IgnorePURLPatterns []*regexp.Regexp
}

var cfg = Config{
	SBOMPath:         "compliance/sbom/traefik.cdx.json",
	LicenseMapPath:   "compliance/config/license-map.json",
	HTMLTemplatePath: "compliance/templates/third_party_licenses.gotpl",
	NoticeTplPath:    "compliance/templates/notice.gotpl",

	OutDir:           "third_party",
	OutLicensesDir:   "third_party/licenses",
	CustomLicenseDir: "compliance/custom-license-texts",

	SPDXVersion: "v3.27.0",

	IgnorePURLPatterns: []*regexp.Regexp{
		regexp.MustCompile(`use\.local`),
	},
}

type SBOM struct {
	Components []Component `json:"components"`
}

type Component struct {
	Name      string          `json:"name"`
	Version   string          `json:"version"`
	PURL      string          `json:"purl"`
	Copyright string          `json:"copyright"`
	Licenses  []LicenseChoice `json:"licenses"`
}

type LicenseChoice struct {
	Expression string `json:"expression"`
	License    *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"license"`
}

type OutComponent struct {
	Name       string
	Version    string
	PURL       string
	URL        string
	LicenseIDs []string
	Copyright  string
}

type LicenseBlock struct {
	ID     string
	Name   string
	Text   string
	UsedBy []OutComponent
}

type OverviewItem struct {
	ID    string
	Name  string
	Count int
}

type Model struct {
	GeneratedAt string
	Overview    []OverviewItem
	Licenses    []LicenseBlock
	Notices     []OutComponent
}

func writeText(p, s string) {
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	_ = os.WriteFile(p, []byte(s), 0o644)
}

func fetchText(ctx context.Context, url string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "oss-attributions-generator")

	client := &http.Client{Timeout: 20 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		io.Copy(io.Discard, res.Body)
		return "", fmt.Errorf("http %d for %s", res.StatusCode, url)
	}

	b, err := io.ReadAll(res.Body)
	return string(b), err
}

func loadSpdxNameMap(ctx context.Context) (map[string]string, error) {
	url := fmt.Sprintf("https://raw.githubusercontent.com/spdx/license-list-data/%s/json/licenses.json", cfg.SPDXVersion)
	body, err := fetchText(ctx, url)
	if err != nil {
		return nil, err
	}

	var payload struct {
		Licenses []struct {
			ID   string `json:"licenseId"`
			Name string `json:"name"`
		} `json:"licenses"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		return nil, err
	}

	out := make(map[string]string, len(payload.Licenses))
	for _, l := range payload.Licenses {
		out[l.ID] = l.Name
	}
	return out, nil
}

func getLicenseText(ctx context.Context, licenseID string) (string, error) {
	cachePath := filepath.Join(cfg.OutLicensesDir, licenseID+".txt")
	if b, err := os.ReadFile(cachePath); err == nil {
		return string(b), nil
	}

	if strings.HasPrefix(licenseID, "LicenseRef-") {
		customPath := filepath.Join(cfg.CustomLicenseDir, licenseID+".txt")
		b, err := os.ReadFile(customPath)
		if err != nil {
			msg := "Missing custom license text: " + customPath
			writeText(cachePath, msg)
			return msg, nil
		}
		writeText(cachePath, string(b))
		return string(b), nil
	}

	url := fmt.Sprintf("https://raw.githubusercontent.com/spdx/license-list-data/%s/text/%s.txt", cfg.SPDXVersion, licenseID)
	txt, err := fetchText(ctx, url)
	if err != nil {
		msg := fmt.Sprintf("Could not fetch SPDX text for %s from %s\nError: %v\nMap it to a valid SPDX id or add a LicenseRef text.",
			licenseID, url, err)
		writeText(cachePath, msg)
		return msg, nil
	}

	writeText(cachePath, txt)
	return txt, nil
}

func normalizeLicenseIDs(licenses []LicenseChoice, licenseMap map[string]string, spdxNames map[string]string) []string {
	var ids []string

	for _, item := range licenses {
		if item.License != nil && item.License.ID != "" {
			ids = append(ids, item.License.ID)
			continue
		}

		expr := strings.TrimSpace(firstNonEmpty(item.Expression, func() string {
			if item.License != nil {
				return item.License.Name
			}
			return ""
		}))
		if expr == "" {
			continue
		}

		if mapped, ok := licenseMap[expr]; ok && mapped != "" {
			ids = append(ids, mapped)
			continue
		}

		split := spdxexp.SplitLicenses(strings.ToLower(expr))
		for _, l := range split {
			lic := spdxexp.Normalize(l)
			if extracted := spdxexp.Normalize(lic); spdxNames[extracted] != "" {
				ids = append(ids, extracted)
				continue
			}
			ids = append(ids, "LicenseRef-UNKNOWN-"+sanitizeID(expr, 40))
		}
	}

	return uniqSorted(ids)
}

func componentURLFromPurl(purl string) string {
	re := regexp.MustCompile(`^pkg:([^/]+)/(.+)@([^@]+)$`)
	m := re.FindStringSubmatch(purl)
	if len(m) != 4 {
		return ""
	}
	typ := m[1]
	name := m[2]

	switch typ {
	case "npm":
		return "https://www.npmjs.com/package/" + name
	case "pypi":
		return "https://pypi.org/project/" + name + "/"
	case "golang":
		if strings.HasPrefix(name, "github.com/") {
			parts := strings.Split(name, "/")
			if len(parts) >= 3 {
				return "https://github.com/" + parts[1] + "/" + parts[2]
			}
		}
		return "https://pkg.go.dev/" + name
	default:
		return ""
	}
}

func buildIndex(components []Component, licenseMap map[string]string, spdxNames map[string]string) (map[string][]OutComponent, map[string]OutComponent) {
	byLicense := map[string][]OutComponent{}
	byKey := map[string]OutComponent{}

	for _, c := range components {
		if shouldIgnorePURL(c.PURL) {
			continue
		}

		ids := normalizeLicenseIDs(c.Licenses, licenseMap, spdxNames)

		out := OutComponent{
			Name:       c.Name,
			Version:    c.Version,
			PURL:       c.PURL,
			URL:        componentURLFromPurl(c.PURL),
			LicenseIDs: ids,
			Copyright:  c.Copyright,
		}

		key := c.PURL
		if key == "" {
			key = c.Name + "@" + c.Version
		}

		if existing, ok := byKey[key]; ok {
			existing.LicenseIDs = uniqSorted(append(existing.LicenseIDs, out.LicenseIDs...))
			if existing.Copyright == "" && out.Copyright != "" {
				existing.Copyright = out.Copyright
			}
			byKey[key] = existing
			out = existing
		} else {
			byKey[key] = out
		}

		for _, id := range ids {
			byLicense[id] = append(byLicense[id], out)
		}
	}

	return byLicense, byKey
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sbom := mustReadJSON[SBOM](cfg.SBOMPath)
	licenseMap := mustReadJSON[map[string]string](cfg.LicenseMapPath)

	spdxNames, err := loadSpdxNameMap(ctx)
	dieIf(err)

	byLicense, byKey := buildIndex(sbom.Components, licenseMap, spdxNames)

	dieIf(os.MkdirAll(cfg.OutDir, 0o755))
	dieIf(os.MkdirAll(cfg.OutLicensesDir, 0o755))

	// Build license blocks in stable order
	licenseIDs := make([]string, 0, len(byLicense))
	for id := range byLicense {
		licenseIDs = append(licenseIDs, id)
	}
	sort.Strings(licenseIDs)

	licenses := make([]LicenseBlock, 0, len(licenseIDs))
	for _, id := range licenseIDs {
		comps := byLicense[id]
		sort.Slice(comps, func(i, j int) bool {
			return comps[i].Name+comps[i].Version < comps[j].Name+comps[j].Version
		})

		name := spdxNames[id]
		if name == "" {
			name = id
		}

		text, err := getLicenseText(ctx, id)
		dieIf(err)

		licenses = append(licenses, LicenseBlock{
			ID:     id,
			Name:   name,
			Text:   text,
			UsedBy: comps,
		})
	}

	overview := make([]OverviewItem, 0, len(licenses))
	for _, l := range licenses {
		overview = append(overview, OverviewItem{ID: l.ID, Name: l.Name, Count: len(l.UsedBy)})
	}
	sort.Slice(overview, func(i, j int) bool {
		if overview[i].Count != overview[j].Count {
			return overview[i].Count > overview[j].Count
		}
		return overview[i].ID < overview[j].ID
	})

	notices := make([]OutComponent, 0, len(byKey))
	for _, c := range byKey {
		if strings.TrimSpace(c.Copyright) != "" {
			notices = append(notices, c)
		}
	}
	sort.Slice(notices, func(i, j int) bool {
		return notices[i].Name+notices[i].Version < notices[j].Name+notices[j].Version
	})

	model := Model{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Overview:    overview,
		Licenses:    licenses,
		Notices:     notices,
	}

	htmlOut := renderHTML(cfg.HTMLTemplatePath, model)
	noticeOut := renderText(cfg.NoticeTplPath, model)

	writeText(filepath.Join(cfg.OutDir, "THIRD_PARTY_LICENSES_GO.html"), htmlOut)
	writeText(filepath.Join(cfg.OutDir, "NOTICE_GO.md"), noticeOut)

	var unknowns []string
	for _, l := range licenses {
		if strings.HasPrefix(l.ID, "LicenseRef-UNKNOWN-") {
			unknowns = append(unknowns, l.ID)
		}
	}
	if len(unknowns) > 0 {
		fmt.Fprintln(os.Stderr, "ERROR: Unknown license expressions found. Add mappings in compliance/config/license-map.json:")
		for _, u := range unknowns {
			fmt.Fprintln(os.Stderr, "-", u)
		}
		os.Exit(2)
	}

	fmt.Printf("Wrote:\n- %s\n- %s\n- %s/\n",
		filepath.Join(cfg.OutDir, "THIRD_PARTY_LICENSES_GO.html"),
		filepath.Join(cfg.OutDir, "NOTICE_GO.md"),
		cfg.OutLicensesDir,
	)
}

func shouldIgnorePURL(purl string) bool {
	if purl == "" {
		return false
	}
	for _, re := range cfg.IgnorePURLPatterns {
		if re.MatchString(purl) {
			return true
		}
	}
	return false
}

func renderHTML(tplPath string, model any) string {
	tpl := template.Must(template.ParseFiles(tplPath))
	var buf bytes.Buffer
	dieIf(tpl.Execute(&buf, model))
	return buf.String()
}

func renderText(tplPath string, model any) string {
	tpl := texttpl.Must(texttpl.ParseFiles(tplPath))
	var buf bytes.Buffer
	dieIf(tpl.Execute(&buf, model))
	return buf.String()
}

func mustReadJSON[T any](path string) T {
	b, err := os.ReadFile(path)
	dieIf(err)
	var out T
	dieIf(json.Unmarshal(b, &out))
	return out
}

func uniqSorted(in []string) []string {
	m := make(map[string]struct{}, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" {
			m[s] = struct{}{}
		}
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sanitizeID(s string, max int) string {
	s = regexp.MustCompile(`[^A-Za-z0-9]+`).ReplaceAllString(s, "-")
	if len(s) > max {
		s = s[:max]
	}
	return strings.Trim(s, "-")
}

func firstNonEmpty(a string, b func() string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b()
}

func dieIf(err error) {
	if err == nil {
		return
	}
	if errors.Is(err, context.DeadlineExceeded) {
		fmt.Fprintln(os.Stderr, "timeout:", err)
	} else {
		fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(1)
}
