package main

import (
	"fmt"
	"strings"
)

// maxSummary bounds the lines of a change that a notice keeps.
const maxSummary = 200

// summary gives the change from the expectations before to those after,
// both canonical texts with one line for each set: "- <line>" for each line
// of before that after lacks, in the order of before, then "+ <line>" for
// each line of after that before lacks, in the order of after. So a changed
// set gives one line of each. Beyond maxSummary lines, one line counts the
// rest.
func summary(before, after string) []string {
	old, cur := textLines(before), textLines(after)
	var out []string
	out = appendMissing(out, "- ", old, cur)
	out = appendMissing(out, "+ ", cur, old)
	if len(out) > maxSummary {
		out = append(out[:maxSummary], fmt.Sprintf("and %d more lines", len(out)-maxSummary))
	}
	return out
}

func textLines(text string) []string {
	if text == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(text, "\n"), "\n")
}

// appendMissing appends mark and each line of from that other lacks.
func appendMissing(out []string, mark string, from, other []string) []string {
	has := make(map[string]bool, len(other))
	for _, l := range other {
		has[l] = true
	}
	for _, l := range from {
		if !has[l] {
			out = append(out, mark+l)
		}
	}
	return out
}
