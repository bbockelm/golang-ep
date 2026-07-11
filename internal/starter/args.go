package starter

import (
	"strings"

	"github.com/PelicanPlatform/classad/classad"
)

// splitV2Raw tokenizes HTCondor's V2 "raw" syntax, used by both the Arguments
// and Environment job-ad attributes (src/condor_utils/condor_arglist.cpp,
// ArgList::AppendArgsV2Raw): tokens are separated by whitespace; a section
// wrapped in single quotes protects whitespace (and quote characters); inside a
// quoted section a doubled single quote ('') is a literal single quote.
// Backslash has no special meaning. This is the exact inverse of the storage
// format golang-htcondor's submit package produces (processNewStyleArguments).
func splitV2Raw(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	tokenStarted := false // distinguishes an explicit empty token ('') from nothing
	i := 0
	for i < len(s) {
		ch := s[i]
		switch {
		case inQuote && ch == '\'' && i+1 < len(s) && s[i+1] == '\'':
			// Doubled quote inside a quoted section: literal single quote.
			cur.WriteByte('\'')
			i += 2
		case ch == '\'':
			inQuote = !inQuote
			tokenStarted = true
			i++
		case !inQuote && (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r'):
			if tokenStarted || cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
				tokenStarted = false
			}
			i++
		default:
			cur.WriteByte(ch)
			tokenStarted = true
			i++
		}
	}
	if tokenStarted || cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// jobArgs extracts the job's argument vector (NOT including argv[0]) from the
// job ad: the V2 "Arguments" attribute (raw syntax, split by splitV2Raw) wins;
// the legacy V1 "Args" attribute falls back to a plain whitespace split with
// \" unescaping (the only escape V1 defines).
func jobArgs(jobAd *classad.ClassAd) []string {
	if v, ok := jobAd.EvaluateAttrString("Arguments"); ok && strings.TrimSpace(v) != "" {
		return splitV2Raw(v)
	}
	if v, ok := jobAd.EvaluateAttrString("Args"); ok && strings.TrimSpace(v) != "" {
		return strings.Fields(strings.ReplaceAll(v, `\"`, `"`))
	}
	return nil
}

// jobEnv extracts the job's environment from the job ad as an ordered list of
// KEY=VALUE strings: the V2 "Environment" attribute (raw syntax:
// whitespace-separated name=value tokens with single-quote quoting) wins; the
// legacy V1 "Env" attribute falls back to a best-effort split on the V1
// delimiters (';' and '|').
func jobEnv(jobAd *classad.ClassAd) []string {
	if v, ok := jobAd.EvaluateAttrString("Environment"); ok && strings.TrimSpace(v) != "" {
		return splitV2Raw(v)
	}
	if v, ok := jobAd.EvaluateAttrString("Env"); ok && strings.TrimSpace(v) != "" {
		var out []string
		for _, tok := range strings.FieldsFunc(v, func(r rune) bool { return r == ';' || r == '|' }) {
			if tok = strings.TrimSpace(tok); tok != "" {
				out = append(out, tok)
			}
		}
		return out
	}
	return nil
}
