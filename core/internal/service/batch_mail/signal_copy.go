package batch_mail

import "strings"

// SignalCopy maps machine-readable signal names to human-readable pain point
// descriptions suitable for use in tier_2 outreach email copy.
var SignalCopy = map[string]string{
	"multiple_providers":    "managing multiple locations",
	"running_ads":           "investing in paid advertising",
	"high_reviews":          "a strong online reputation",
	"premium_services":      "offering premium services",
	"affluent_zip":          "serving an affluent market",
	"no_chat":               "missing live chat on your website",
	"voicemail_after_hrs":   "calls going to voicemail after hours",
	"no_online_booking":     "no online self-scheduling for clients",
	"slow_form":             "slow response times on contact forms",
	"high_spend_low_rating": "high ad spend with room to improve reviews",
	"owner_email":           "being hands-on with the business",
	"active_social":         "being active on social media",
	"industry_community":    "being involved in industry communities",
}

// SignalsToCopy converts a comma-separated signal string into a slice of
// human-readable descriptions using SignalCopy.
func SignalsToCopy(signals string) []string {
	if signals == "" {
		return nil
	}
	parts := strings.Split(signals, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if copy, ok := SignalCopy[p]; ok {
			result = append(result, copy)
		}
	}
	return result
}
