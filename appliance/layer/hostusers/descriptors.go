// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package hostusers

import "github.com/olivaresai/olivares/appliance/layer/hostops"

func Descriptors() []hostops.Descriptor {
	return []hostops.Descriptor{{ID: "host-user.create", Module: "host-user", Verb: "create", Title: "Create an OS account", Category: "System",
		InputSchema:   hostops.InputSchema{Type: "object", Properties: map[string]hostops.InputField{"account": {Type: "string"}, "home": {Type: "string"}, "group": {Type: "string"}}, Required: []string{"account", "group"}},
		Preconditions: []string{"Current host-system authority", "Existing primary group", "New account and absent /home/<account>"},
		Consequence:   "Create a locked-password OS account and its private home. Product users and workspaces are unchanged.", Confirmation: "confirm", Modes: []string{"product-up"}, ActVerb: "system", Audience: "appliance-helper:olivares-portal-system",
		EquivalentCommand: "olivares-appliance host-user create <account> --group <group>", OutputSchema: "hostop-v1.schema.json", Surfaces: []string{"web", "cli", "tui"}}}
}
