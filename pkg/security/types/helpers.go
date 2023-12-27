/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"regexp"
	"strings"
)

func MakeID(val string) string {
	reg, _ := regexp.Compile("[^A-Za-z0-9]+")
	return strings.Trim(reg.ReplaceAllString(strings.ToLower(val), "-"), "- ")
}

func contains(a []string, x string) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}

func containsCaseInsensitiveAny(a []string, x ...string) bool {
	for _, n := range a {
		for _, c := range x {
			if strings.TrimSpace(strings.ToLower(c)) == strings.TrimSpace(strings.ToLower(n)) {
				return true
			}
		}
	}
	return false
}

func IsTaggedWithBaseTag(tags []string, baseTag string) bool { // base tags are before the colon ":" like in "aws:ec2" it's "aws". The subtag is after the colon. Also, a pure "aws" tag matches the base tag "aws"
	baseTag = strings.ToLower(strings.TrimSpace(baseTag))
	for _, tag := range tags {
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag == baseTag || strings.HasPrefix(tag, baseTag+":") {
			return true
		}
	}
	return false
}

type byDataAssetTitleSort []DataAsset

func (what byDataAssetTitleSort) Len() int      { return len(what) }
func (what byDataAssetTitleSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what byDataAssetTitleSort) Less(i, j int) bool {
	return what[i].Title < what[j].Title
}
