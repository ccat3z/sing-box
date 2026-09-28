package main

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

func readOptionsFromContent(t *testing.T, content string) *OptionsEntry {
	t.Helper()
	options, err := json.UnmarshalExtendedContext[option.Options](globalCtx, []byte(content))
	require.NoError(t, err)
	return &OptionsEntry{
		content: []byte(content),
		path:    "test.json",
		options: options,
	}
}

func TestMergeRulePriority(t *testing.T) {
	globalCtx = include.Context(service.ContextWith[deprecated.Manager](context.Background(), deprecated.NewStderrManager(log.StdLogger())))

	baseConfig := `{
		"log": {"level": "info"},
		"dns": {
			"servers": [{"type": "udp", "tag": "dnslocal", "server": "1.1.1.1"}],
			"rules": [
				{"domain": ["dns-base.example.com"], "server": "dnslocal", "priority": 50}
			]
		},
		"inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}],
		"outbounds": [{"type": "direct", "tag": "direct"}],
		"route": {
			"rules": [
				{"domain": ["base.example.com"], "action": "reject", "priority": 100}
			]
		}
	}`
	overrideConfig := `{
		"route": {
			"rules": [
				{"domain": ["high.example.com"], "action": "reject", "priority": -5},
				{"domain": ["mid.example.com"], "action": "reject", "priority": 50}
			]
		},
		"dns": {
			"rules": [
				{"domain": ["dns-high.example.com"], "server": "dnslocal", "priority": -5}
			]
		}
	}`

	mergedOptions, err := mergeOptionsList([]*OptionsEntry{
		readOptionsFromContent(t, baseConfig),
		readOptionsFromContent(t, overrideConfig),
	})
	require.NoError(t, err)

	require.Equal(t, []string{
		"high.example.com",
		"mid.example.com",
		"base.example.com",
	}, collectRouteRuleDomains(mergedOptions))

	require.Equal(t, []int{-5, 50, 100}, collectRouteRulePriorities(mergedOptions))

	require.Equal(t, []string{
		"dns-high.example.com",
		"dns-base.example.com",
	}, collectDNSRuleDomains(mergedOptions))
}

func collectRouteRuleDomains(options option.Options) []string {
	domains := make([]string, 0, len(options.Route.Rules))
	for _, rule := range options.Route.Rules {
		domains = append(domains, rule.DefaultOptions.Domain[0])
	}
	return domains
}

func collectRouteRulePriorities(options option.Options) []int {
	priorities := make([]int, 0, len(options.Route.Rules))
	for _, rule := range options.Route.Rules {
		priorities = append(priorities, rule.Priority)
	}
	return priorities
}

func collectDNSRuleDomains(options option.Options) []string {
	domains := make([]string, 0, len(options.DNS.Rules))
	for _, rule := range options.DNS.Rules {
		domains = append(domains, rule.DefaultOptions.Domain[0])
	}
	return domains
}
