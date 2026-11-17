package start

import (
	"github.com/Opsek/dns-monitoring/internal/config"
	"github.com/Opsek/dns-monitoring/internal/deliver"
	"github.com/Opsek/dns-monitoring/internal/httpclient"
)

// Channels gives the channels of a config in the order of its Channels
// names: Slack when it is set, then each webhook. A message sent through them
// takes the path of every alert.
func Channels(c *config.Config, v config.Values, client *httpclient.Client) []deliver.Channel {
	var channels []deliver.Channel
	if c.Slack != nil {
		channels = append(channels, deliver.NewSlack(client, v.SlackURL, c.Slack.MinSeverity))
	}
	for i, h := range c.Webhooks {
		channels = append(channels, deliver.NewWebhook(client, h.Name, v.WebhookURLs[i], v.WebhookKeys[i], h.MinSeverity))
	}
	return channels
}
