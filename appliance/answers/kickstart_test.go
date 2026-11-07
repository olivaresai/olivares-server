// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package answers_test

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/olivaresai/olivares/appliance/answers"
)

// Every answers document the Anaconda kickstarts write in %post is one first boot accepts: with the
// administrator deferred, and without (a wheel administrator, root with a key, a desktop with no accounts).
func TestAnacondaKickstartAnswersAreAccepted(t *testing.T) {
	const header = "cat >/etc/olivares-appliance/answers.json <<EOF\n"
	for _, edition := range []string{"server", "desktop"} {
		data, err := os.ReadFile("../images/anaconda/" + edition + ".ks")
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		start := strings.Index(text, header)
		end := strings.Index(text[start+len(header):], "\nEOF\n")
		if start < 0 || end < 0 {
			t.Fatalf("%s: the %%post answers document was not found", edition)
		}
		template := text[start+len(header) : start+len(header)+end]
		var values []string
		for _, m := range regexp.MustCompile(`(?m)^ *administrator=([a-z]+)$`).FindAllStringSubmatch(text, -1) {
			values = append(values, m[1])
		}
		if strings.Join(values, " ") != "installed deferred" {
			t.Fatalf("%s: want the administrator states installed then deferred, got %q", edition, values)
		}
		for _, administrator := range values {
			doc := strings.NewReplacer("$hostname", "olivares-server", "$administrator", administrator).Replace(template)
			if _, err := answers.Build(strings.NewReader(doc)); err != nil {
				t.Errorf("%s %%post answers with administrator %q were refused: %v", edition, administrator, err)
			}
		}
	}
}
