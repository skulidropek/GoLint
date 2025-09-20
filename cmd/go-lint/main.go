package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type position struct {
	Filename string `json:"filename"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
}

type issue struct {
	FromLinter string   `json:"FromLinter"`
	Text       string   `json:"Text"`
	Severity   string   `json:"Severity"`
	Source     string   `json:"Source"`
	Pos        position `json:"Pos"`
}

type report struct {
	Issues []issue `json:"Issues"`
}

type analyzerConfig struct {
	Name     string   `json:"name"`
	Command  []string `json:"command"`
	Severity string   `json:"severity"`
}

type lintConfig struct {
	Analyzers      []analyzerConfig `json:"analyzers"`
	PriorityLevels []priorityLevel  `json:"priorityLevels"`
}

type priorityLevel struct {
	Level int      `json:"level"`
	Name  string   `json:"name"`
	Rules []string `json:"rules"`
}

const maxPrintedIssues = 15

func runExtraAnalyzers(args []string, cfg lintConfig) []issue {
	configs := mergeAnalyzerConfigs(cfg)
	if len(configs) == 0 {
		return nil
	}

	targets := args
	if len(targets) == 0 {
		targets = []string{"./..."}
	}

	var collected []issue
	for _, cfg := range configs {
		if cfg.Name == "" {
			continue
		}
		if len(cfg.Command) == 0 {
			cfg.Command = []string{cfg.Name}
		}
		severity := normalizeSeverity(cfg.Severity)
		for _, target := range targets {
			cmdline := expandCommand(cfg.Command, target)
			if len(cmdline) == 0 {
				continue
			}
			out, err := exec.Command(cmdline[0], cmdline[1:]...).CombinedOutput()
			if len(out) > 0 {
				collected = append(collected, parseGoDiagnostics(out, cfg.Name, severity)...)
			}
			if err != nil && !isExitError(err) {
				fmt.Fprintf(os.Stderr, "❌ %s failed: %v\n", cfg.Name, err)
				if len(out) > 0 {
					printSanitized(out)
				}
			}
		}
	}

	return collected
}

func mergeAnalyzerConfigs(cfg lintConfig) []analyzerConfig {
	merged := map[string]analyzerConfig{}
	for _, auto := range detectAutoAnalyzers() {
		merged[auto.Name] = auto
	}
	for _, user := range cfg.Analyzers {
		if user.Name == "" {
			continue
		}
		merged[user.Name] = user
	}

	result := make([]analyzerConfig, 0, len(merged))
	for _, v := range merged {
		result = append(result, v)
	}

	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func loadConfig() lintConfig {
	paths := []string{"go-lint.config.json", ".go-lint.config.json"}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			fmt.Fprintf(os.Stderr, "❌ could not read %s: %v\n", p, err)
			continue
		}
		var cfg lintConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "❌ could not parse %s: %v\n", p, err)
			continue
		}
		return cfg
	}
	return lintConfig{}
}

func detectAutoAnalyzers() []analyzerConfig {
	var list []analyzerConfig
	if commandExists("smbgo") {
		list = append(list, analyzerConfig{
			Name:     "smbgo",
			Command:  []string{"smbgo", "{target}"},
			Severity: "error",
		})
	}
	return list
}

func buildPriorityIndex(levels []priorityLevel) map[string]int {
	index := make(map[string]int, len(levels))
	for _, lvl := range levels {
		if lvl.Level <= 0 {
			continue
		}
		for _, rule := range lvl.Rules {
			if rule == "" {
				continue
			}
			index[strings.ToLower(rule)] = lvl.Level
		}
	}
	return index
}

func filterByPriority(issues []issue, level int, priorities map[string]int) []issue {
	if len(priorities) == 0 {
		return nil
	}
	var filtered []issue
	for _, is := range issues {
		if priorityValue(is, priorities) == level {
			filtered = append(filtered, is)
		}
	}
	return filtered
}

func commandExists(name string) bool {
	if name == "" {
		return false
	}
	_, err := exec.LookPath(name)
	return err == nil
}

func expandCommand(parts []string, target string) []string {
	if len(parts) == 0 {
		return nil
	}
	expanded := make([]string, len(parts))
	containsPlaceholder := false
	for i, part := range parts {
		replaced := strings.ReplaceAll(part, "{target}", target)
		replaced = strings.ReplaceAll(replaced, "${target}", target)
		expanded[i] = replaced
		if replaced != part {
			containsPlaceholder = true
		}
	}
	if !containsPlaceholder && target != "" {
		expanded = append(expanded, target)
	}
	return expanded
}

func normalizeSeverity(sev string) string {
	switch strings.ToLower(sev) {
	case "error":
		return "error"
	case "warn", "warning":
		return "warning"
	case "info", "information":
		return "info"
	case "":
		return "error"
	default:
		return strings.ToLower(sev)
	}
}

func parseGoDiagnostics(out []byte, linterName, severity string) []issue {
	text := strings.ReplaceAll(string(out), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	var items []issue
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		match := goDiagnosticPattern.FindStringSubmatch(line)
		if len(match) != 5 {
			continue
		}
		ln, err1 := strconv.Atoi(match[2])
		col, err2 := strconv.Atoi(match[3])
		if err1 != nil || err2 != nil {
			continue
		}
		messageLines := []string{strings.TrimSpace(match[4])}
		nextIndex := i + 1
		for nextIndex < len(lines) {
			next := lines[nextIndex]
			trimmed := strings.TrimSpace(next)
			if trimmed == "" {
				messageLines = append(messageLines, "")
				nextIndex++
				continue
			}
			if goDiagnosticPattern.MatchString(trimmed) {
				break
			}
			messageLines = append(messageLines, strings.TrimRight(next, "\r"))
			nextIndex++
		}
		items = append(items, issue{
			FromLinter: linterName,
			Text:       strings.Join(messageLines, "\n"),
			Severity:   severity,
			Source:     linterName,
			Pos: position{
				Filename: match[1],
				Line:     ln,
				Column:   col,
			},
		})
		i = nextIndex - 1
	}
	return items
}

var goDiagnosticPattern = regexp.MustCompile(`^(.+?):(\d+):(\d+):\s*(.+)$`)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		args = []string{"./..."}
	}

	fmt.Printf("🔍 Linting target: %s\n", strings.Join(args, " "))

	if err := runGoFmt(args); err != nil {
		fmt.Fprintf(os.Stderr, "❌ go fmt завершился с ошибкой: %v\n", err)
	}

	if err := runFix(args); err != nil {
		fmt.Fprintf(os.Stderr, "❌ golangci-lint --fix failed: %v\n", err)
	}

	raw, runErr := runLintJSON(args)
	if len(raw) == 0 {
		if runErr != nil {
			fmt.Fprintf(os.Stderr, "❌ golangci-lint run failed: %v\n", runErr)
			os.Exit(1)
		}
		fmt.Println("📊 Total: 0 errors, 0 warnings.")
		return
	}

	var rep report
	jsonBytes, err := extractJSON(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ could not parse golangci-lint JSON output: %v\n", err)
		printSanitized(raw)
		os.Exit(1)
	}
	if err := json.Unmarshal(jsonBytes, &rep); err != nil {
		fmt.Fprintf(os.Stderr, "❌ could not decode golangci-lint JSON output: %v\n", err)
		printSanitized(raw)
		os.Exit(1)
	}

	cfg := loadConfig()
	extraIssues := runExtraAnalyzers(args, cfg)
	if len(extraIssues) > 0 {
		rep.Issues = append(rep.Issues, extraIssues...)
	}

	if len(rep.Issues) == 0 {
		fmt.Println("📊 Total: 0 errors, 0 warnings.")
		return
	}

	priorityIndex := buildPriorityIndex(cfg.PriorityLevels)
	rep.Issues = dedupeIssues(rep.Issues)
	sortIssues(rep.Issues, priorityIndex)

	totalErrors := 0
	totalWarnings := 0
	for _, is := range rep.Issues {
		switch strings.ToLower(is.Severity) {
		case "error":
			totalErrors++
		case "warning":
			totalWarnings++
		}
	}

	cache := map[string][]string{}
	absCache := map[string]string{}

	levels := append([]priorityLevel(nil), cfg.PriorityLevels...)
	sort.SliceStable(levels, func(i, j int) bool { return levels[i].Level < levels[j].Level })
	issuesToPrint := rep.Issues
	printedHeader := false
	for _, lvl := range levels {
		if lvl.Level <= 0 {
			continue
		}
		group := filterByPriority(rep.Issues, lvl.Level, priorityIndex)
		if len(group) == 0 {
			continue
		}
		fmt.Printf("\n=== Level %d: %s (%d issues) ===\n", lvl.Level, lvl.Name, len(group))
		issuesToPrint = group
		printedHeader = true
		break
	}
	if !printedHeader {
		fmt.Printf("\n=== Issues (%d items) ===\n", len(issuesToPrint))
	}

	printed := 0
	for _, is := range issuesToPrint {
		if printed >= maxPrintedIssues {
			continue
		}
		printed++

		label := labelForSeverity(is.Severity)
		displayPath := is.Pos.Filename
		absPath := resolvePath(displayPath, absCache)

		fmt.Printf("\n%s %s:%d:%d @%s — %s\n", label, displayPath, is.Pos.Line, is.Pos.Column, is.FromLinter, strings.TrimSpace(is.Text))
		printContext(absPath, is.Pos.Line, is.Pos.Column, cache)

		if doc := ruleDocURL(is); doc != "" {
			fmt.Printf(" 📖 docs: %s\n", doc)
		}

		query := searchKey(is)
		fmt.Println(" 💡 Search for similar fixes")
		fmt.Printf(" 🔍 so: https://api.stackexchange.com/2.3/search/advanced?order=desc&sort=relevance&q=%s&site=stackoverflow&pagesize=5\n", query)
		fmt.Printf(" 🔍 gh: https://api.github.com/search/issues?q=%s+in:title\n", query)
	}

	fmt.Printf("\n📊 Total: %d errors, %d warnings.\n", totalErrors, totalWarnings)

	if totalErrors > 0 {
		os.Exit(1)
	}
}

func runFix(args []string) error {
	cmdArgs := append([]string{"run", "--fix"}, args...)
	cmd := exec.Command("golangci-lint", cmdArgs...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}

func runGoFmt(args []string) error {
	cmdArgs := append([]string{"fmt"}, args...)
	cmd := exec.Command("go", cmdArgs...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}

func runLintJSON(args []string) ([]byte, error) {
	cmdArgs := append([]string{"run", "--out-format", "json", "--show-stats", "false"}, args...)
	cmd := exec.Command("golangci-lint", cmdArgs...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	return stdout.Bytes(), err
}

func isExitError(err error) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr)
}

func sortIssues(issues []issue, priorities map[string]int) {
	sort.SliceStable(issues, func(i, j int) bool {
		si := severityRank(issues[i].Severity)
		sj := severityRank(issues[j].Severity)
		if si != sj {
			return si > sj
		}
		pi := priorityValue(issues[i], priorities)
		pj := priorityValue(issues[j], priorities)
		if pi != pj {
			return pi < pj
		}
		if issues[i].Pos.Filename != issues[j].Pos.Filename {
			return issues[i].Pos.Filename < issues[j].Pos.Filename
		}
		if issues[i].Pos.Line != issues[j].Pos.Line {
			return issues[i].Pos.Line < issues[j].Pos.Line
		}
		return issues[i].Pos.Column < issues[j].Pos.Column
	})
}

func priorityValue(is issue, priorities map[string]int) int {
	if len(priorities) == 0 {
		return math.MaxInt32
	}
	key := strings.ToLower(is.FromLinter)
	if lvl, ok := priorities[key]; ok {
		return lvl
	}
	return math.MaxInt32
}

func dedupeIssues(list []issue) []issue {
	type key struct {
		file   string
		line   int
		column int
		linter string
	}

	seen := make(map[key]issue)
	order := make([]key, 0, len(list))

	for _, is := range list {
		canonical := canonicalPath(is.Pos.Filename)
		k := key{
			file:   canonical,
			line:   is.Pos.Line,
			column: is.Pos.Column,
			linter: strings.ToLower(is.FromLinter),
		}
		if existing, ok := seen[k]; ok {
			if preferIssue(existing, is) {
				seen[k] = is
			}
		} else {
			seen[k] = is
			order = append(order, k)
		}
	}

	result := make([]issue, 0, len(order))
	for _, k := range order {
		result = append(result, seen[k])
	}
	return result
}

func preferIssue(current, candidate issue) bool {
	curRank := severityRank(current.Severity)
	candRank := severityRank(candidate.Severity)
	if candRank != curRank {
		return candRank > curRank
	}
	curHint := strings.Contains(strings.ToLower(current.Text), "did you mean")
	candHint := strings.Contains(strings.ToLower(candidate.Text), "did you mean")
	if candHint != curHint {
		return candHint
	}
	if len(candidate.Text) != len(current.Text) {
		return len(candidate.Text) > len(current.Text)
	}
	return false
}

func canonicalPath(p string) string {
	if p == "" {
		return ""
	}
	if abs, err := filepath.Abs(p); err == nil {
		return strings.ToLower(abs)
	}
	return strings.ToLower(filepath.Clean(p))
}

func severityRank(sev string) int {
	switch strings.ToLower(sev) {
	case "error":
		return 3
	case "warning":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

func labelForSeverity(sev string) string {
	switch strings.ToLower(sev) {
	case "error":
		return "[ERROR]"
	case "warning":
		return "[WARN ]"
	default:
		return "[INFO ]"
	}
}

func resolvePath(path string, cache map[string]string) string {
	if path == "" {
		return ""
	}
	if abs, ok := cache[path]; ok {
		return abs
	}
	abs := path
	if !filepath.IsAbs(path) {
		if resolved, err := filepath.Abs(path); err == nil {
			abs = resolved
		}
	}
	cache[path] = abs
	return abs
}

func printContext(path string, line, column int, cache map[string][]string) {
	if path == "" {
		fmt.Println(" (Could not determine file path for context)")
		return
	}

	lines, err := loadFileLines(path, cache)
	if err != nil {
		fmt.Printf(" (Could not read file for context: %v)\n", err)
		return
	}

	if line <= 0 || line > len(lines) {
		fmt.Println(" (Context not available: invalid line number)")
		return
	}

	start := line - 2
	if start < 1 {
		start = 1
	}
	end := line + 1
	if end > len(lines) {
		end = len(lines)
	}

	for i := start; i <= end; i++ {
		marker := " "
		if i == line {
			marker = ">"
		}
		prefix := fmt.Sprintf(" %s %4d | ", marker, i)
		fmt.Println(prefix + lines[i-1])
		if i == line {
			highlight(prefix, lines[i-1], column)
		}
	}
}

func loadFileLines(path string, cache map[string][]string) ([]string, error) {
	if lines, ok := cache[path]; ok {
		return lines, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	cache[path] = lines
	return lines, nil
}

func highlight(prefix, line string, column int) {
	if column < 1 {
		column = 1
	}
	highlightCol := column - 1
	if highlightCol > len(line) {
		highlightCol = len(line)
	}
	caretLine := strings.Repeat(" ", len(prefix)+highlightCol) + "^"
	fmt.Println(caretLine)
}

func ruleDocURL(is issue) string {
	code := staticcheckCode(is.Text)
	if code != "" {
		return "https://staticcheck.dev/docs/checks#" + code
	}
	switch strings.ToLower(is.FromLinter) {
	case "govet":
		return "https://pkg.go.dev/cmd/vet"
	case "revive":
		return "https://revive.run/"
	}
	return ""
}

var staticcheckPattern = regexp.MustCompile(`\b(?:SA\d{4}|S\d{4}|ST\d{4})\b`)

func staticcheckCode(text string) string {
	return staticcheckPattern.FindString(text)
}

func searchKey(is issue) string {
	if code := staticcheckCode(is.Text); code != "" {
		return urlQuery(code)
	}
	if strings.ToLower(is.FromLinter) == "govet" {
		return urlQuery("go vet " + firstWords(is.Text, 6))
	}
	if strings.ToLower(is.FromLinter) == "revive" {
		head := strings.SplitN(strings.TrimSpace(is.Text), ":", 2)[0]
		if head != "" {
			return urlQuery("revive " + head)
		}
	}
	return urlQuery(is.FromLinter + " " + firstWords(is.Text, 6))
}

func firstWords(text string, n int) string {
	fields := strings.Fields(text)
	if len(fields) <= n {
		return strings.Join(fields, " ")
	}
	return strings.Join(fields[:n], " ")
}

func urlQuery(text string) string {
	replacer := strings.NewReplacer(
		" ", "%20",
		"\n", "%0A",
		"\t", "%09",
		"\"", "%22",
		"'", "%27",
	)
	return replacer.Replace(text)
}

func extractJSON(raw []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(raw)
	start := bytes.IndexByte(trimmed, '{')
	end := bytes.LastIndexByte(trimmed, '}')
	if start == -1 || end == -1 || start > end {
		return nil, fmt.Errorf("no JSON object in output")
	}
	candidate := trimmed[start : end+1]
	if !bytes.Contains(candidate, []byte(`"Issues"`)) {
		return nil, fmt.Errorf("unexpected payload before JSON")
	}
	return candidate, nil
}

func printSanitized(raw []byte) {
	cleaned := bytes.TrimSpace(raw)
	if len(cleaned) == 0 {
		return
	}
	if len(cleaned) > 4096 {
		cleaned = append(cleaned[:4093], '.', '.', '.')
	}
	fmt.Println(string(cleaned))
}
