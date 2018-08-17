package pii

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gen0cide/waiter"
)

// TestSettings are used to set the test harness settings
type TestSettings struct {
	DetectPII bool `json:"detect_pii,omitempty" csv:"detect_pii"`
	FindPII   bool `json:"find_pii,omitempty" csv:"find_pii"`
}

// Metric is used to record the efficencies of matches
type Metric struct {
	DetectionLatencies map[string]float64 `json:"detection_latencies,omitempty" csv:"detection_latencies"`
	MatchLatencies     map[string]float64 `json:"match_latencies,omitempty" csv:"match_latencies"`
}

// Tester defines a test harness for assessment
type Tester struct {
	TestSettings
	Metric
	Rules []Rule  `json:"rules,omitempty" csv:"rules"`
	Files []*File `json:"files,omitempty" csv:"files"`
}

// File defines a specific file that is to be tested
type File struct {
	sync.RWMutex
	Metric
	Filename     string              `json:"filename,omitempty" csv:"filename"`
	Path         string              `json:"path,omitempty" csv:"path"`
	Hits         map[string]bool     `json:"hits,omitempty" csv:"hits"`
	Matches      map[string][]string `json:"matches,omitempty" csv:"matches"`
	Errored      bool                `json:"errored,omitempty" csv:"errored"`
	ErrorMessage string              `json:"error_message,omitempty" csv:"error_message"`
	RuleCache    []Rule              `json:"-"`
	Data         []byte              `json:"-"`
}

// NewEmptyTester returns an empty Test harness with no rules loaded
func NewEmptyTester() *Tester {
	return &Tester{
		Rules:  []Rule{},
		Files:  []*File{},
		Metric: emptyMetric(),
	}
}

func emptyMetric() Metric {
	return Metric{
		DetectionLatencies: map[string]float64{},
		MatchLatencies:     map[string]float64{},
	}
}

// NewDefaultTester creates a new default Test harness with all default rules included
func NewDefaultTester() *Tester {
	t := NewEmptyTester()
	for _, r := range DefaultRuleSet {
		t.Rules = append(t.Rules, r)
	}
	return t
}

// SetDetection sets the tester's detect PII setting
func (t *Tester) SetDetection(s bool) {
	t.DetectPII = s
}

// SetFinder sets the tester's find PII setting
func (t *Tester) SetFinder(s bool) {
	t.FindPII = s
}

// CalcAverages is used to calculate the averages of all the file matching metrics
func (t *Tester) CalcAverages() {
	for _, r := range t.Rules {
		dtotal := float64(0)
		dcount := float64(0)
		ftotal := float64(0)
		fcount := float64(0)
		for _, x := range t.Files {
			if x.Errored {
				continue
			}
			dtotal += x.DetectionLatencies[r.Name]
			dcount++
			if x.Hits[r.Name] {
				ftotal += x.MatchLatencies[r.Name]
				fcount++
			}
		}
		if dcount == 0 {
			continue
		}
		t.DetectionLatencies[r.Name] = dtotal / dcount
		if fcount > 0 {
			t.MatchLatencies[r.Name] = ftotal / fcount
		}
	}
}

// NewSubsetRuleTester returns a TestHarness with only a section of rules
func NewSubsetRuleTester(rules ...string) (*Tester, error) {
	t := NewEmptyTester()
	for _, r := range rules {
		rule, ok := DefaultRuleSet[r]
		if !ok {
			return nil, fmt.Errorf("%s is not a valid default rule", r)
		}
		t.Rules = append(t.Rules, rule)
	}
	return t, nil
}

// AddNewFile adds a new file to the test harness
func (t *Tester) AddNewFile(f string) error {
	if _, err := os.Stat(f); err != nil {
		return err
	}
	t.Files = append(t.Files, NewFile(f))
	return nil
}

// AddRecursiveDirectory adds all files recursively in a directory to the test harness
func (t *Tester) AddRecursiveDirectory(d string) error {
	return errors.New("add directories recursively has not been implemented yet")
}

// NewFile returns a generic file object
func NewFile(f string) *File {
	return &File{
		Filename: filepath.Base(f),
		Path:     f,
		Hits:     map[string]bool{},
		Matches:  map[string][]string{},
		Metric:   emptyMetric(),
	}
}

func (f *File) Error() string {
	return fmt.Sprintf("file error with %s: %s", f.Path, f.ErrorMessage)
}

// PerformDetections performs all detections against a given Test Harness
func (t *Tester) PerformDetections(w *waiter.Waiter) []error {
	errors := []error{}
	if w == nil {
		w = waiter.New("", ioutil.Discard)
	}
	if len(t.Files) == 0 {
		return nil
	}
	if len(t.Rules) == 0 {
		return nil
	}
	w.Reset("pii_detection")
	errChan := make(chan error, 1)
	finChan := make(chan bool, 1)
	go func() {
		for {
			select {
			case err := <-errChan:
				errors = append(errors, err)
			case <-finChan:
				return
			}
		}
	}()

	for _, f := range t.Files {
		w.Add(1)
		go f.Load(w, errChan)
	}

	w.Wait()
	close(finChan)
	return errors
}

// PerformMatches performs all matches against a given Test Harness
func (t *Tester) PerformMatches(w *waiter.Waiter) {
	if w == nil {
		w = waiter.New("", ioutil.Discard)
	}
	if len(t.Files) == 0 {
		return
	}
	if len(t.Rules) == 0 {
		return
	}
	w.Reset("pii_matcher")

	for _, f := range t.Files {
		w.Add(1)
		go f.Find(w)
	}

	w.Wait()
}

// Load loads the file into memory and proceeds with the test
func (f *File) Load(w *waiter.Waiter, errChan chan error) {
	defer w.Done()
	data, err := ioutil.ReadFile(f.Path)
	if err != nil {
		f.Errored = true
		f.ErrorMessage = err.Error()
		errChan <- f
		return
	}
	f.Data = data
	w.Add(1)
	go f.Detect(w)
}

// Find performs all cached match rules on a given file
func (f *File) Find(w *waiter.Waiter) {
	defer w.Done()
	if f.Errored {
		return
	}
	for _, r := range f.RuleCache {
		if f.Hits[r.Name] == false {
			continue
		}
		w.Add(1)
		go f.FindOnRule(r, w)
	}
}

// FindOnRule performs a single export on a file with a given rule
func (f *File) FindOnRule(rule Rule, w *waiter.Waiter) {
	defer w.Done()
	ts := time.Now()
	lines := strings.Split(string(f.Data), "\n")
	matches := []string{}
	for _, x := range lines {
		matches = append(matches, rule.Exporter(x)...)
	}
	dur := time.Since(ts).Nanoseconds()
	f.Lock()
	defer f.Unlock()
	f.Matches[rule.Name] = matches
	f.MatchLatencies[rule.Name] = float64(dur) / float64(time.Millisecond)
	return
}

// Detect performs all cached detection rules on a given file
func (f *File) Detect(w *waiter.Waiter) {
	defer w.Done()
	for _, r := range f.RuleCache {
		w.Add(1)
		go f.DetectOnRule(r, w)
	}
}

// DetectOnRule performs a single detection on a file with a given rule
func (f *File) DetectOnRule(rule Rule, w *waiter.Waiter) {
	defer w.Done()
	ts := time.Now()
	lines := strings.Split(string(f.Data), "\n")
	matched := false
	for _, x := range lines {
		matched = rule.Filter(x)
		if matched {
			break
		}
	}
	dur := time.Since(ts).Nanoseconds()
	f.Lock()
	defer f.Unlock()
	f.Hits[rule.Name] = matched
	f.DetectionLatencies[rule.Name] = float64(dur) / float64(time.Millisecond)
	return
}

// Setup prepares the files for matching
func (t *Tester) Setup() {
	wg := new(sync.WaitGroup)

	for _, f := range t.Files {
		wg.Add(1)
		go func(rules []Rule, file *File) {
			defer wg.Done()
			for _, r := range rules {
				if t.DetectPII {
					file.Hits[r.Name] = false
				}
				if t.FindPII {
					file.Matches[r.Name] = []string{}
				}
			}
			file.RuleCache = rules
		}(t.Rules, f)
	}

	wg.Wait()
}
