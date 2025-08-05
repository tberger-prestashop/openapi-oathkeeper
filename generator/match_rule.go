package generator

import (
	"log"
	"regexp"
	"strings"

	"github.com/cerberauth/openapi-oathkeeper/oathkeeper"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/hedhyw/rex/pkg/dialect"
	"github.com/hedhyw/rex/pkg/rex"
)

var (
	argre = regexp.MustCompile(`(?m)({(.*)})`)

	numberToken = rex.Group.Define(
		rex.Group.Composite(
			rex.Chars.Single('-'),
			rex.Chars.Single('+'),
		).Repeat().ZeroOrOne(),
		rex.Chars.Digits().Repeat().OneOrMore(),
		rex.Group.NonCaptured(
			rex.Chars.Single('.'),
			rex.Chars.Digits().Repeat().OneOrMore(),
		).Repeat().ZeroOrOne(),
	)
	integerToken = rex.Chars.Digits().Repeat().OneOrMore()
	stringToken  = rex.Common.Class(
			rex.Chars.Alphanumeric(),
			rex.Chars.Single('_'),
			rex.Chars.Single('-'),
		).Repeat().OneOrMore()
	defaultToken = rex.Chars.Any().Repeat().OneOrMore()
)

func encapsulateRegex(r *regexp.Regexp) string {
	// URL Regexp is encapsulated in brackets: https://www.ory.sh/docs/oathkeeper/api-access-rules#access-rule-format
	return "<" + r.String() + ">"
}

func encapsulateRegexToken(t dialect.Token) string {
	return encapsulateRegex(rex.New(t).MustCompile())
}

func createServerUrlMatchingGroup(serverUrls []string) string {
	if len(serverUrls) == 0 {
		return ""
	}

	if len(serverUrls) == 1 {
		return strings.TrimSuffix(serverUrls[0], "/")
	}

	var serverUrlsTokens []dialect.Token
	for _, serverUrl := range serverUrls {
		serverUrlsTokens = append(serverUrlsTokens, rex.Common.Text(serverUrl))
	}

	return encapsulateRegexToken(rex.Group.Composite(serverUrlsTokens...))
}

func getPathParamSchema(name string, params *openapi3.Parameters) *openapi3.Schema {
	if params == nil {
		log.Default().Print("no path parameters has been defined")
		return nil
	}

	p := params.GetByInAndName(openapi3.ParameterInPath, name)
	if p == nil {
		log.Default().Printf("path param %s is not defined", name)
		return nil
	}
	return p.Schema.Value
}

func createParamsMatchingGroup(name string, params *openapi3.Parameters) string {
	var t dialect.Token
	paramSchema := getPathParamSchema(name, params)
	switch paramType := paramSchema.Type; {
	case paramType.Is("string"):
		if len(paramSchema.Enum) > 0 {
			
			// Handle case with enum schema = {"enum":["dev","staging","prod"],"type":"string"}
			enumTokens := make([]dialect.Token, 0, len(paramSchema.Enum))
			enumTokens = append(enumTokens, rex.Chars.Begin())
			for _, enumValue := range paramSchema.Enum {
				enumTokens = append(enumTokens, rex.Common.Text(enumValue.(string)))
			}
			enumTokens = append(enumTokens, rex.Chars.End())
			t = rex.Group.Composite(enumTokens...)
		} else {
			// Default case for string type
			t = stringToken
		}
	case paramType.Is("number"):
		t = numberToken
	case paramType.Is("integer"):
		t = integerToken
	default:
		t = defaultToken
	}

	return encapsulateRegexToken(t)
}

func createMatchRule(serverUrls []string, v string, p string, params *openapi3.Parameters) (*oathkeeper.RuleMatch, error) {
	pathTokens := []string{createServerUrlMatchingGroup(serverUrls)}
	for _, dir := range strings.Split(p, "/") {
		if dir == "" {
			continue
		}

		if matches := argre.FindStringSubmatch(dir); len(matches) > 0 {
			pathTokens = append(pathTokens, createParamsMatchingGroup(string(matches[2]), params))
		} else {
			pathTokens = append(pathTokens, dir)
		}
	}

	u := strings.Join(pathTokens, "/")
	match := &oathkeeper.RuleMatch{
		URL:     u,
		Methods: []string{v},
	}

	return match, nil
}
