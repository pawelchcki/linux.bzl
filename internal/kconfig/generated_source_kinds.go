package kconfig

import (
	"fmt"
	"path"
	"strings"
)

// The generator registry.
//
// Rule *discovery* is generic: kbuild_generated_source.go derives which rule
// produces a leaf object's source from the parsed Makefile. Rule *execution*
// cannot be, and this file is where that is admitted.
//
// No action in this project has an awk, shell, sed or coreutils toolchain. The
// only interpreter available is Perl. Everything else is a Go program under
// internal/cmd/ reimplementing a kernel generator. So a newly discovered rule
// can be described precisely and still have no way to run, and the honest
// outcome is a failure that names the Makefile line rather than a guess.
//
// The registry is keyed on the canonicalised *command text*, never on the
// command's name. 6.12 spells the same generator "cmd_perlasm" on x86 and
// "cmd_perl" on arm; 6.18 moves both to lib/crypto and adds
// "cmd_perlasm_with_args". The text is what actually determines behaviour, it
// is derived from the Makefile rather than transcribed from it, and it is
// shared across kernel versions and architectures.
//
// This is still a hardcoded table. It is a better-shaped one: keyed on
// something derived, failing loudly on a miss, and naming the two files to
// edit when it does.

// GeneratedSourceKind names an executor this project can actually run.
type GeneratedSourceKind string

const (
	GeneratedSourceKindNone GeneratedSourceKind = ""
	// GeneratedSourcePerlStdout runs a perlasm script and captures stdout.
	// 6.12 arch/x86/crypto and arch/arm/crypto, 6.18 lib/crypto/{arm,x86}.
	GeneratedSourcePerlStdout GeneratedSourceKind = "perl_stdout"
	// GeneratedSourcePerlArgOut passes the output path as an argument after a
	// literal flavour word. 6.12 arch/arm64/crypto, 6.18 lib/crypto/arm64.
	GeneratedSourcePerlArgOut GeneratedSourceKind = "perl_arg_out"
	// GeneratedSourceRaid6Unroll expands lib/raid6's ".uc" templates.
	GeneratedSourceRaid6Unroll GeneratedSourceKind = "raid6_unroll"
	// GeneratedSourceMkcapflags builds arch/x86/kernel/cpu/capflags.c.
	GeneratedSourceMkcapflags GeneratedSourceKind = "mkcapflags"
	// GeneratedSourceConmakehash builds drivers/tty/vt/consolemap_deftbl.c.
	GeneratedSourceConmakehash GeneratedSourceKind = "conmakehash"
	// GeneratedSourceRaid6Mktables builds lib/raid6/tables.c.
	GeneratedSourceRaid6Mktables GeneratedSourceKind = "raid6_mktables"
)

// generatedSourceKindSpec describes one executable generator.
//
// Every field is declared rather than inferred. Which prerequisite is the
// nominal source, which ones the executor actually opens, and which ones only
// need to be digest-covered are all properties of the executor, and guessing
// any of them produces either a sandbox failure or a stale-cache bug.
type generatedSourceKindSpec struct {
	kind GeneratedSourceKind
	// canonical is the canonicalised command text this kind recognises.
	canonical string
	// primary picks the nominal source recorded for the object. It is not
	// always $<: mkcapflags binds $< to cpufeatures.h, but the source that
	// stands for the object is the script.
	primary func(KbuildGeneratedSource) string
	// actionInputs are prerequisites the executor opens at run time and that
	// therefore must be declared as action inputs.
	actionInputs func(KbuildGeneratedSource) []string
	// digestOnlyInputs are files whose contents must invalidate the object but
	// which the action never reads, because a Go port stands in for them.
	digestOnlyInputs func(KbuildGeneratedSource) []string
	// args are the executor arguments beyond the input and output paths.
	args func(KbuildGeneratedSource) []string
}

// generatedSourceKinds is the closed set of executable generators.
//
// Deliberately absent: "PERL $< <flavour> > $@", used by powerpc and mips
// perlasm. Those scripts spawn a "*-xlate.pl" child, which the sandbox has no
// way to declare. Only x86, arm64 and arm are supported architectures, so the
// shape is unreachable; it stays UNKNOWN rather than half-implemented.
var generatedSourceKinds = []generatedSourceKindSpec{
	{
		kind:      GeneratedSourcePerlStdout,
		canonical: "PERL $< > $@",
		primary:   func(gs KbuildGeneratedSource) string { return gs.Primary },
		actionInputs: func(gs KbuildGeneratedSource) []string {
			return []string{gs.Primary}
		},
	},
	{
		kind:      GeneratedSourcePerlArgOut,
		canonical: "PERL $< void $@",
		primary:   func(gs KbuildGeneratedSource) string { return gs.Primary },
		actionInputs: func(gs KbuildGeneratedSource) []string {
			return []string{gs.Primary}
		},
		args: func(KbuildGeneratedSource) []string { return []string{"void"} },
	},
	{
		kind:      GeneratedSourceRaid6Unroll,
		canonical: "AWK -v N=$* -f %[unroll] < $< > $@",
		primary:   func(gs KbuildGeneratedSource) string { return gs.Primary },
		actionInputs: func(gs KbuildGeneratedSource) []string {
			return []string{gs.Primary}
		},
		// unroll.awk is reimplemented by internal/cmd/unroll, so the action
		// never opens it, but a change to it changes the generated source.
		digestOnlyInputs: func(gs KbuildGeneratedSource) []string {
			return generatedSourcePrerequisitesExcept(gs, gs.Primary)
		},
		args: func(gs KbuildGeneratedSource) []string { return []string{"-n", gs.Stem} },
	},
	{
		kind:      GeneratedSourceMkcapflags,
		canonical: "SHELL %[script] $@ $^",
		// $< here is cpufeatures.h, but the source that stands for capflags.o
		// is the script. Preserving that keeps the object's identity stable
		// across the move onto this resolver.
		primary: func(gs KbuildGeneratedSource) string {
			return generatedSourceScriptPrerequisite(gs, ".sh")
		},
		// The Go port reads all three: both feature headers and the script.
		actionInputs: func(gs KbuildGeneratedSource) []string {
			return append([]string{}, gs.Prerequisites...)
		},
	},
	{
		kind:      GeneratedSourceConmakehash,
		canonical: "HOSTPROG(conmakehash) $< > $@",
		primary:   func(gs KbuildGeneratedSource) string { return gs.Primary },
		actionInputs: func(gs KbuildGeneratedSource) []string {
			return []string{gs.Primary}
		},
		// conmakehash is a hostprog reimplemented in Go. Nothing currently
		// invalidates consolemap_deftbl.o when the upstream hostprog changes;
		// digesting its source closes that hole.
		digestOnlyInputs: func(gs KbuildGeneratedSource) []string {
			return generatedSourceHostprogSources(gs)
		},
	},
	{
		kind:      GeneratedSourceRaid6Mktables,
		canonical: "HOSTPROG(mktables) > $@",
		// The generator takes no input file at all; it writes tables.c from
		// compiled-in knowledge.
		primary: func(KbuildGeneratedSource) string { return "" },
		digestOnlyInputs: func(gs KbuildGeneratedSource) []string {
			return generatedSourceHostprogSources(gs)
		},
	},
}

// GeneratedSourceExecutor is a resolved generator: a kind plus the concrete
// inputs and arguments the action needs.
type GeneratedSourceExecutor struct {
	Kind GeneratedSourceKind
	// Primary is the nominal source recorded for the object. It always names a
	// real checked-in file, never the generated target, because several
	// invariants require the object's source to exist in the tree and be part
	// of the exact-input group.
	Primary string
	// ActionInputs are files the action opens, in rule order.
	ActionInputs []string
	// DigestOnlyInputs are files that must invalidate the object without being
	// action inputs.
	DigestOnlyInputs []string
	// Args are executor arguments beyond input and output.
	Args []string
}

// GeneratedSourceExecutorFor classifies a resolved rule into an executor.
//
// It fails rather than guessing. The error names the object, the resolved
// target, the rule position, the command name, the canonical command text and
// the two files that need editing, because that is the whole point of deriving
// dispatch from rules: an unsupported generator becomes an actionable report
// instead of a silent wrong answer.
func GeneratedSourceExecutorFor(object string, gs KbuildGeneratedSource) (GeneratedSourceExecutor, error) {
	canonical, err := canonicalGeneratedSourceCommand(gs)
	if err != nil {
		return GeneratedSourceExecutor{}, generatedSourceKindError(object, gs, canonical, err)
	}
	for _, spec := range generatedSourceKinds {
		if spec.canonical != canonical {
			continue
		}
		executor := GeneratedSourceExecutor{
			Kind:    spec.kind,
			Primary: spec.primary(gs),
		}
		if spec.actionInputs != nil {
			executor.ActionInputs = spec.actionInputs(gs)
		}
		if spec.digestOnlyInputs != nil {
			executor.DigestOnlyInputs = spec.digestOnlyInputs(gs)
		}
		if spec.args != nil {
			executor.Args = spec.args(gs)
		}
		if executor.Primary == "" && spec.kind != GeneratedSourceRaid6Mktables {
			return GeneratedSourceExecutor{}, generatedSourceKindError(
				object, gs, canonical,
				fmt.Errorf("the rule has no prerequisite that can stand for the object's source"))
		}
		return executor, nil
	}
	return GeneratedSourceExecutor{}, generatedSourceKindError(object, gs, canonical, nil)
}

func generatedSourceKindError(object string, gs KbuildGeneratedSource, canonical string, cause error) error {
	position := gs.Position.Filename
	if position == "" {
		position = gs.Directory + "/Makefile"
	}
	detail := ""
	if cause != nil {
		detail = ": " + cause.Error()
	}
	return fmt.Errorf(
		"no generator is implemented for leaf object %q, whose source %q is produced by "+
			"cmd_%s at %s:%d%s\n"+
			"  command:   %s\n"+
			"  canonical: %s\n"+
			"Add the kind to internal/kconfig/generated_source_kinds.go and a matching "+
			"branch to _linux_generated_source in internal/linux_objects.bzl.",
		object, gs.Target, gs.CommandName, position, gs.Position.Line, detail,
		gs.CommandTemplate, canonical)
}

// canonicalGeneratedSourceCommand reduces a command body to a comparable form.
//
// Whitespace collapses, the parenthesised automatic-variable spellings fold
// into the short ones, and the leading program word becomes a token so that a
// literal "$(PERL)" and a resolved interpreter path classify identically.
// In-tree script paths become placeholders, because the same generator lives
// at a different path in every kernel version.
//
// It fails closed: any "$(...)" that is not an automatic variable and survives
// this reduction means the command was not fully understood.
func canonicalGeneratedSourceCommand(gs KbuildGeneratedSource) (string, error) {
	fields := strings.Fields(foldMakeAutomaticVariables(gs.CommandTemplate))
	if len(fields) == 0 {
		return "", fmt.Errorf("the command is empty")
	}
	program, err := canonicalGeneratedSourceProgram(fields[0])
	if err != nil {
		return "", err
	}
	out := make([]string, 0, len(fields))
	out = append(out, program)
	for _, field := range fields[1:] {
		out = append(out, canonicalGeneratedSourceWord(field, gs))
	}
	canonical := strings.Join(out, " ")
	for _, reference := range makeVariableRefs(canonical) {
		if isMakeAutomaticVariable(reference) {
			continue
		}
		return canonical, fmt.Errorf(
			"the command still references $(%s), which is not an automatic variable", reference)
	}
	return canonical, nil
}

// canonicalGeneratedSourceProgram classifies the leading word of a command.
//
// PERL, AWK and CONFIG_SHELL are not part of the default variable environment,
// because only arch/<srcarch>/Makefile is parsed, so they normally survive
// expansion as literal references. That is not an invariant: "-var" is
// user-populated and module_make_vars are merged in, so a consumer can define
// them, in which case they arrive as a resolved interpreter path. Both forms
// have to classify the same, which is why this tokenises instead of comparing
// strings.
func canonicalGeneratedSourceProgram(word string) (string, error) {
	switch word {
	case "$(PERL)", "${PERL}":
		return "PERL", nil
	case "$(AWK)", "${AWK}":
		return "AWK", nil
	case "$(CONFIG_SHELL)", "${CONFIG_SHELL}", "$(SHELL)", "${SHELL}":
		return "SHELL", nil
	}
	if containsMakeReference(word) {
		return "", fmt.Errorf("the leading program word %q is an unrecognised make reference", word)
	}
	switch strings.ToLower(path.Base(word)) {
	case "perl":
		return "PERL", nil
	case "awk", "gawk", "mawk":
		return "AWK", nil
	case "sh", "bash", "dash":
		return "SHELL", nil
	}
	// An in-tree path with no extension is a hostprog built from the kernel
	// tree, which this project reimplements in Go. Its basename is part of the
	// token, because which hostprog it is determines what runs.
	if strings.ContainsRune(word, '/') && path.Ext(word) == "" {
		return "HOSTPROG(" + path.Base(word) + ")", nil
	}
	return "", fmt.Errorf("the leading program word %q is not a recognised interpreter or hostprog", word)
}

// canonicalGeneratedSourceWord replaces in-tree paths with placeholders so the
// canonical form is version- and architecture-independent.
func canonicalGeneratedSourceWord(word string, gs KbuildGeneratedSource) string {
	if !strings.ContainsRune(word, '/') {
		return word
	}
	base := path.Base(word)
	switch {
	case base == "unroll.awk":
		return "%[unroll]"
	case strings.HasSuffix(base, ".sh"):
		return "%[script]"
	}
	return word
}

// foldMakeAutomaticVariables rewrites the parenthesised spellings of make's
// automatic variables into the short ones. 6.12 writes "$(<)" on arm and arm64
// but "$<" on x86 for what is otherwise the same command.
func foldMakeAutomaticVariables(command string) string {
	replacer := strings.NewReplacer(
		"$(<)", "$<", "${<}", "$<",
		"$(@)", "$@", "${@}", "$@",
		"$(*)", "$*", "${*}", "$*",
		"$(^)", "$^", "${^}", "$^",
	)
	return replacer.Replace(command)
}

// generatedSourcePrerequisitesExcept returns the non-primary prerequisites.
func generatedSourcePrerequisitesExcept(gs KbuildGeneratedSource, exclude string) []string {
	out := make([]string, 0, len(gs.Prerequisites))
	for _, prerequisite := range gs.Prerequisites {
		if prerequisite == exclude {
			continue
		}
		out = append(out, prerequisite)
	}
	return out
}

// generatedSourceScriptPrerequisite picks the prerequisite with the given
// extension, which is how a script-driven generator names its own script.
func generatedSourceScriptPrerequisite(gs KbuildGeneratedSource, extension string) string {
	for _, prerequisite := range gs.Prerequisites {
		if strings.HasSuffix(prerequisite, extension) {
			return prerequisite
		}
	}
	return ""
}

// generatedSourceHostprogSources maps extension-less hostprog prerequisites to
// the C source they are built from, which is the file that must be digested.
func generatedSourceHostprogSources(gs KbuildGeneratedSource) []string {
	var out []string
	for _, prerequisite := range gs.Prerequisites {
		if path.Ext(prerequisite) != "" {
			continue
		}
		out = append(out, prerequisite+".c")
	}
	return out
}
