package latest

import (
	"fmt"
)

// TaintConfig is the top-level `taints:` block. See
// docs/design/taint-tracking.md for the conceptual design and
// pkg/taint for the runtime contract.
type TaintConfig struct {
	// Classes declares every taint class the agent recognises, keyed by
	// class name. Two seed classes (`secret`, `public`) are defaulted
	// when this map is empty; declaring any class disables defaulting
	// so users can opt out of `public`/`secret` if they want a custom
	// vocabulary.
	Classes map[string]TaintClass `json:"classes,omitempty" yaml:"classes,omitempty"`

	// Forbid is the matrix that turns the active taint set into a
	// hard-deny verdict on a tool call. Rules are OR'd; any match
	// denies. See ForbidRule.
	Forbid []ForbidRule `json:"forbid,omitempty" yaml:"forbid,omitempty"`

	// Tags maps tool-argument shapes (paths, env vars, URLs) onto the
	// classes they introduce. Drives the automatic propagator: e.g.
	// reading a file matching `**/.env*` introduces `secret`.
	Tags TaintTags `json:"tags,omitempty" yaml:"tags,omitempty"`
}

// TaintClass describes a single class. The runtime treats classes as
// opaque names; the description is for human reviewers reading the
// YAML.
type TaintClass struct {
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// ForbidRule denies a tool call when every class in When.Active is
// currently active in the session AND any class in ToolWritesTo
// appears in the tool's declared write set.
type ForbidRule struct {
	When         ForbidWhen `json:"when" yaml:"when"`
	ToolWritesTo []string   `json:"tool_writes_to" yaml:"tool_writes_to"`
}

// ForbidWhen is the precondition for a ForbidRule. Active is a set of
// class names; the rule fires only when every name is currently
// active.
type ForbidWhen struct {
	Active []string `json:"active" yaml:"active"`
}

// TaintTags hosts the path/env/url tables. Each table is a list of
// match rules (glob) plus the classes to add when the match hits.
type TaintTags struct {
	Paths []TaintTagRule `json:"paths,omitempty" yaml:"paths,omitempty"`
	Env   []TaintTagRule `json:"env,omitempty"   yaml:"env,omitempty"`
	URLs  []TaintTagRule `json:"urls,omitempty"  yaml:"urls,omitempty"`
}

// TaintTagRule pairs a glob pattern with the classes to introduce.
type TaintTagRule struct {
	Match string   `json:"match" yaml:"match"`
	Add   []string `json:"add"   yaml:"add"`
}

// ToolsetTaints declares the per-toolset read/write classes. Reads is
// the set of classes the toolset's tools are assumed to read from;
// Writes is the set of classes the toolset's tools are assumed to
// write to. The runtime picks the more conservative of this and the
// built-in classifier defaults.
type ToolsetTaints struct {
	Reads  []string `json:"reads,omitempty"  yaml:"reads,omitempty"`
	Writes []string `json:"writes,omitempty" yaml:"writes,omitempty"`
}

// UnmarshalYAML wraps the default decode with the local validate so
// typos in the forbid matrix surface at parse time, where a YAML
// reviewer will see them.
func (t *TaintConfig) UnmarshalYAML(unmarshal func(any) error) error {
	type alias TaintConfig
	var tmp alias
	if err := unmarshal(&tmp); err != nil {
		return err
	}
	*t = TaintConfig(tmp)
	return t.validate()
}

// validate catches the rule violations that don't depend on any
// outside state: forbid rules reference classes that exist (in the
// declared set or the seed defaults), tag rules carry a non-empty
// match.
func (t *TaintConfig) validate() error {
	known := t.knownClasses()
	for i, r := range t.Forbid {
		for _, c := range r.When.Active {
			if !known[c] {
				return fmt.Errorf("taints.forbid[%d].when.active references unknown class %q", i, c)
			}
		}
		for _, c := range r.ToolWritesTo {
			if !known[c] {
				return fmt.Errorf("taints.forbid[%d].tool_writes_to references unknown class %q", i, c)
			}
		}
	}
	for i, r := range t.Tags.Paths {
		if r.Match == "" {
			return fmt.Errorf("taints.tags.paths[%d].match must be set", i)
		}
		for _, c := range r.Add {
			if !known[c] {
				return fmt.Errorf("taints.tags.paths[%d].add references unknown class %q", i, c)
			}
		}
	}
	for i, r := range t.Tags.Env {
		if r.Match == "" {
			return fmt.Errorf("taints.tags.env[%d].match must be set", i)
		}
		for _, c := range r.Add {
			if !known[c] {
				return fmt.Errorf("taints.tags.env[%d].add references unknown class %q", i, c)
			}
		}
	}
	for i, r := range t.Tags.URLs {
		if r.Match == "" {
			return fmt.Errorf("taints.tags.urls[%d].match must be set", i)
		}
		for _, c := range r.Add {
			if !known[c] {
				return fmt.Errorf("taints.tags.urls[%d].add references unknown class %q", i, c)
			}
		}
	}
	return nil
}

// knownClasses returns the recognised class names for this config:
// the explicit Classes map, or the seed defaults (`secret`, `public`,
// `privileged`) when no classes are declared. `privileged` is always
// recognised because it names "the privileged side" used in forbid
// rules; the other seeds are dropped only when the user supplies
// their own classes.
func (t *TaintConfig) knownClasses() map[string]bool {
	known := map[string]bool{"privileged": true}
	if len(t.Classes) == 0 {
		known["secret"] = true
		known["public"] = true
		return known
	}
	for name := range t.Classes {
		known[name] = true
	}
	return known
}

// validateAgainstClasses checks per-toolset taint declarations against
// the top-level class set. Called from Config.validate.
func (tt *ToolsetTaints) validateAgainstClasses(known map[string]bool) error {
	if tt == nil {
		return nil
	}
	for _, c := range tt.Reads {
		if !known[c] {
			return fmt.Errorf("toolset taints.reads references unknown class %q", c)
		}
	}
	for _, c := range tt.Writes {
		if !known[c] {
			return fmt.Errorf("toolset taints.writes references unknown class %q", c)
		}
	}
	return nil
}
