// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package auth

import (
	"go/ast"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// layer is the root of the appliance layer as seen from this package: the console on 9443,
// this sign-in package and the repair console on tty1. Everything the appliance layer runs
// is under it, so a scan rooted here is a scan of the whole of it.
var layer = filepath.Join("..", "..")

// credentialNames matches password storage, derivation or verification, and host secret
// files. Only the reviewed mutable, request-bound PAM ingress below is transient.
var credentialNames = regexp.MustCompile(`(?i)passwd|password|bcrypt|scrypt|argon2|pbkdf2|shadow|keyring`)

// writingIdentifiers lists, per import path, the identifiers that create, write or remove a
// file, or start a process. A console that holds a credential store would need one of them
// to make the store; a console that performs a repair verb would need one of them to
// perform it. Reads are deliberately absent: the console reads the TLS material the
// operator owns, and that material is not a credential of the console's own.
var writingIdentifiers = map[string][]string{
	"os":      {"Create", "CreateTemp", "WriteFile", "OpenFile", "Mkdir", "MkdirAll", "MkdirTemp", "Remove", "RemoveAll", "Rename", "Symlink", "Link", "Chmod", "Chown", "Truncate"},
	"os/exec": {"Command", "CommandContext", "LookPath"},
	"syscall": {"Write", "Creat", "Mknod", "Unlink", "Setuid", "Setgid"},
}

// packageSources parses the non-test Go sources of one directory.
func packageSources(t *testing.T, dir string) []parsed {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var files []parsed
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, parse(t, filepath.Join(dir, name), string(data)))
	}
	if len(files) == 0 {
		t.Fatalf("no non-test sources in %s", dir)
	}
	return files
}

// layerSources parses every non-test Go source of the appliance layer rooted at root.
func layerSources(t *testing.T, root string) []parsed {
	t.Helper()
	files := sourcesUnder(t, root)
	if len(files) < 2 {
		t.Fatalf("the layer scan found %d sources, so it is not looking at the layer", len(files))
	}
	return files
}

// effectFreeDirs are the directories of the layer, at any depth below them, whose sources
// may create no file and start no process: this sign-in package, and the repair console on
// tty1 with its command. They decide who may ask and offer the verbs; they perform nothing.
// The rest of the portal is not here, because its certificate and audit-spool owners write
// by design, and neither are the layer's privileged helpers and base modules, whose effects
// are what they exist for. The credential-name scan still reads all of them.
var effectFreeDirs = []string{"portal/auth", "tui"}

// effectSources parses the sources whose writes and process starts this package's
// invariant forbids, in the layer rooted at root: every non-test source under an
// effect-free directory, a file added there later included, and nothing outside them.
func effectSources(t *testing.T, root string) []parsed {
	t.Helper()
	var files []parsed
	for _, dir := range effectFreeDirs {
		files = append(files, sourcesUnder(t, filepath.Join(root, filepath.FromSlash(dir)))...)
	}
	if len(files) == 0 {
		t.Fatalf("the effect scan found no source under %s, so its silence proves nothing", root)
	}
	return files
}

// sourcesUnder parses every non-test Go source under dir, at any depth.
func sourcesUnder(t *testing.T, dir string) []parsed {
	t.Helper()
	var files []parsed
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		files = append(files, parse(t, path, string(data)))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// identifiers returns every identifier except the exact borrowed request buffers.
// Comments are not identifiers; globals, other fields and hashing still reach the scan.
func identifiers(files []parsed) []string {
	var names []string
	for _, file := range files {
		transient := transientRequestPasswords(file)
		ast.Inspect(file.syntax, func(n ast.Node) bool {
			if ident, ok := n.(*ast.Ident); ok && !transient[ident] {
				names = append(names, file.path+": "+ident.Name)
			}
			return true
		})
	}
	return names
}

// transientRequestPasswords recognizes bindings, never whole files or matching names
// alone. Native PAM owns authentication; its reviewed requestStack borrows the sole
// mutable ingress buffer. Runtime clearing/no-Start/Account proofs stay in the request
// adapter and handler tests. A global, extra field, immutable string or hash is not it.
func transientRequestPasswords(file parsed) map[*ast.Ident]bool {
	allowed := map[*ast.Ident]bool{}
	path := "/" + filepath.ToSlash(filepath.Clean(file.path))
	pam := strings.HasSuffix(path, "/portal/portalpam/stack.go") && file.syntax.Name.Name == "portalpam"
	browser := strings.HasSuffix(path, "/portal/signin.go") && file.syntax.Name.Name == "portal"
	if !pam && !browser {
		return allowed
	}
	mutable := func(expr ast.Expr) bool {
		slice, ok := expr.(*ast.ArrayType)
		if !ok || slice.Len != nil {
			return false
		}
		ident, ok := slice.Elt.(*ast.Ident)
		return ok && ident.Name == "byte"
	}
	borrowed := false
	if pam {
		if obj := file.syntax.Scope.Lookup("requestStack"); obj != nil {
			if spec, ok := obj.Decl.(*ast.TypeSpec); ok {
				if st, ok := spec.Type.(*ast.StructType); ok {
					for _, field := range st.Fields.List {
						for _, name := range field.Names {
							if name.Name == "password" && mutable(field.Type) {
								allowed[name], borrowed = true, true
							}
						}
					}
				}
			}
		}
	}
	// Parents distinguish a direct return from a copied or escaping initializer.
	parents := map[ast.Node]ast.Node{}
	var ancestors []ast.Node
	ast.Inspect(file.syntax, func(node ast.Node) bool {
		if node == nil {
			ancestors = ancestors[:len(ancestors)-1]
			return true
		}
		if len(ancestors) != 0 {
			parents[node] = ancestors[len(ancestors)-1]
		}
		ancestors = append(ancestors, node)
		return true
	})
	for _, decl := range file.syntax.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		receiver, receiverType := "", ""
		if fn.Recv != nil && len(fn.Recv.List) == 1 && len(fn.Recv.List[0].Names) == 1 {
			receiver = fn.Recv.List[0].Names[0].Name
			if ptr, ok := fn.Recv.List[0].Type.(*ast.StarExpr); ok {
				if ident, ok := ptr.X.(*ast.Ident); ok {
					receiverType = ident.Name
				}
			}
		}
		constructor := pam && fn.Name.Name == "NewRequestStack" && fn.Recv == nil && fn.Type.Results != nil &&
			!slices.ContainsFunc(fn.Type.Results.List, func(field *ast.Field) bool { return len(field.Names) != 0 })
		start := pam && borrowed && fn.Name.Name == "Start" && receiverType == "requestStack"
		decode := browser && fn.Name.Name == "signInCredentials" && fn.Recv == nil
		signIn := browser && fn.Name.Name == "signIn" && receiverType == "protectedNetwork"
		if !constructor && !start && !decode && !signIn {
			continue
		}
		var input *ast.Ident
		if constructor {
			for _, field := range fn.Type.Params.List {
				for _, name := range field.Names {
					if name.Name == "password" && mutable(field.Type) {
						input = name
					}
				}
			}
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			if constructor {
				switch n.(type) {
				case *ast.FuncLit, *ast.GoStmt:
					return false // Capturing the input extends its request lifetime.
				}
			}
			switch node := n.(type) {
			case *ast.Ident:
				if node.Name != "password" || node.Obj == nil || node.Obj.Kind != ast.Var {
					break
				}
				switch binding := node.Obj.Decl.(type) {
				case *ast.Field:
					if constructor && input != nil && node.Obj == input.Obj {
						// Declaration, native input validation and builtin clearing do
						// not retain it. Every other use must be the direct return below.
						allowed[node] = allowed[node] || slices.Contains(binding.Names, node)
						if call, ok := parents[node].(*ast.CallExpr); ok {
							if name, ok := call.Fun.(*ast.Ident); ok {
								allowed[node] = name.Name == "clear" && name.Obj == nil && len(call.Args) == 1 && call.Args[0] == node
							}
							if check, ok := call.Fun.(*ast.SelectorExpr); ok {
								if pkg, ok := check.X.(*ast.Ident); ok {
									allowed[node] = pkg.Name == "nativepam" && pkg.Obj == nil && check.Sel.Name == "ValidRequest" && len(call.Args) == 2 && call.Args[1] == node
								}
							}
						}
					}
				case *ast.ValueSpec:
					allowed[node] = decode && mutable(binding.Type)
				case *ast.AssignStmt:
					if signIn && len(binding.Rhs) == 1 {
						if call, ok := binding.Rhs[0].(*ast.CallExpr); ok {
							if name, ok := call.Fun.(*ast.Ident); ok {
								allowed[node] = name.Name == "signInCredentials"
							}
						}
					}
				}
			case *ast.SelectorExpr:
				if owner, ok := node.X.(*ast.Ident); start && ok && owner.Name == receiver && node.Sel.Name == "password" {
					allowed[node.Sel] = true
				}
			case *ast.CompositeLit:
				name, ok := node.Type.(*ast.Ident)
				if !constructor || !borrowed || input == nil || !ok || name.Name != "requestStack" {
					break
				}
				pointer, ok := parents[node].(*ast.UnaryExpr)
				if !ok || pointer.Op != token.AND {
					break
				}
				returned, ok := parents[pointer].(*ast.ReturnStmt)
				if !ok || len(returned.Results) == 0 || returned.Results[0] != pointer || !slices.Contains(fn.Body.List, ast.Stmt(returned)) {
					break
				}
				for _, elt := range node.Elts {
					if pair, ok := elt.(*ast.KeyValueExpr); ok {
						key, named := pair.Key.(*ast.Ident)
						value, direct := pair.Value.(*ast.Ident)
						if named && key.Name == "password" && direct && value.Obj == input.Obj {
							allowed[key], allowed[value] = true, true
						}
					}
				}
			}
			return true
		})
	}
	return allowed
}

// writeSites returns each place in files that creates, writes or removes a file, or starts
// a process, reached through the name the file gives its import or through a dot import.
func writeSites(files []parsed) []string {
	var sites []string
	for _, file := range files {
		imported := map[string]string{}
		for _, spec := range file.syntax.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if _, watched := writingIdentifiers[path]; err != nil || !watched {
				continue
			}
			name := path[strings.LastIndex(path, "/")+1:]
			if spec.Name != nil {
				name = spec.Name.Name
			}
			if name == "." {
				sites = append(sites, file.path+": dot import of "+path)
				continue
			}
			imported[name] = path
		}
		ast.Inspect(file.syntax, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); ok {
				if path, ok := imported[pkg.Name]; ok && slices.Contains(writingIdentifiers[path], sel.Sel.Name) {
					sites = append(sites, file.path+": "+path+"."+sel.Sel.Name)
				}
			}
			return true
		})
	}
	return sites
}

// structFields returns the field names of the named struct type, in order.
func structFields(files []parsed, name string) []string {
	for _, file := range files {
		for _, decl := range file.syntax.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range gen.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok || ts.Name.Name != name {
					continue
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					return nil
				}
				var fields []string
				for _, field := range st.Fields.List {
					for _, ident := range field.Names {
						fields = append(fields, ident.Name)
					}
				}
				return fields
			}
		}
	}
	return nil
}

// credentialChecks counts the calls that check a human's credential in this package's
// non-test sources: a transaction's authentication step, and nothing else.
func credentialChecks(files []parsed) []string {
	var sites []string
	for _, file := range files {
		ast.Inspect(file.syntax, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Authenticate" {
				sites = append(sites, file.path)
			}
			return true
		})
	}
	return sites
}

func TestPortal_HoldsNoPasswordOfItsOwn(t *testing.T) {
	layerFiles := layerSources(t, layer)

	t.Run("nothing in the layer holds a password or hashes one", func(t *testing.T) {
		for _, name := range identifiers(layerFiles) {
			if credentialNames.MatchString(name) {
				t.Errorf("declares or reads %s", name)
			}
		}
		// Control: the scan finds one when there is one, so its silence above is a
		// measurement and not an inability.
		planted := identifiers([]parsed{parse(t, "planted.go", "package p\n\nvar passwordHash []byte\n")})
		if !slices.ContainsFunc(planted, credentialNames.MatchString) {
			t.Fatal("control: the identifier scan does not find a planted credential")
		}
	})

	t.Run("sign-in and the repair console create no file and start no process", func(t *testing.T) {
		for _, site := range writeSites(effectSources(t, layer)) {
			t.Errorf("writes to the host: %s", site)
		}
		// Control: the same scan finds a planted store and a planted helper call.
		for _, src := range []string{
			`package p; import "os"; func f() { os.WriteFile("store", nil, 0o600) }`,
			`package p; import e "os/exec"; func f() { e.Command("helper") }`,
			`package p; import . "os"; func f() { Create("store") }`,
		} {
			if sites := writeSites([]parsed{parse(t, "planted.go", src)}); len(sites) == 0 {
				t.Fatalf("control: the write scan does not find %s", src)
			}
		}
	})

	t.Run("a completed sign-in carries no credential", func(t *testing.T) {
		if fields := structFields(layerFiles, "Offer"); !slices.Equal(fields, []string{"Mode", "Login", "Verbs"}) {
			t.Errorf("an offer carries %v: the mode, the human and the verbs, and nothing else", fields)
		}
		stack := usableStack()
		offer, err := NewSelector(reachable(false), NewPAM(stack)).SignIn(administrator)
		if err != nil {
			t.Fatal(err)
		}
		if offer.Login != administrator || len(offer.Verbs) == 0 {
			t.Fatalf("the sign-in did not complete: %+v", offer)
		}
		// The fake transaction is the only credential check in this run: exactly one, and
		// the stack was asked for it rather than the console deciding it.
		if stack.authenticated != 1 || stack.closed != 1 {
			t.Errorf("the host's stack checked %d credentials and closed %d transactions, want 1 and 1",
				stack.authenticated, stack.closed)
		}
	})

	t.Run("the host's stack is the only credential check in this package", func(t *testing.T) {
		sites := credentialChecks(packageSources(t, "."))
		if len(sites) != 1 {
			t.Errorf("the package checks a credential in %v, want exactly one place", sites)
		}
		for _, site := range sites {
			if filepath.Base(site) != "pam.go" {
				t.Errorf("a credential is checked outside the PAM adapter: %s", site)
			}
		}
	})
}

// TestPortal_ScanReach measures, on a planted layer, how far each scan above reaches.
//
// The effect scan reads sign-in and the repair console: a write planted in any file of
// theirs, a new one included, is found. The rest of the portal writes by design — the
// daemon writes the certificate its helper installs and owns the audit spool — and a
// privileged helper or a base module performs the effects its own owner decides, so a write
// planted there is not this scan's to find. The credential-name scan reads the whole layer,
// so a credential name planted in a helper or beside the audit spool is found.
func TestPortal_ScanReach(t *testing.T) {
	root := t.TempDir()
	plant := func(name, src string) string {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	mustFind := []string{
		plant("portal/auth/store.go",
			`package auth; import "os"; func f() { os.Create("store") }`),
		plant("portal/auth/cache/cache.go",
			`package cache; import . "os"; func f() { MkdirAll("cache", 0o700) }`),
		plant("tui/state.go",
			`package tui; import "os"; func f() { os.WriteFile("state", nil, 0o600) }`),
		plant("tui/cmd/olivares-repair-console/run.go",
			`package main; import e "os/exec"; func f() { e.Command("helper") }`),
	}
	mayWrite := []string{
		plant("portal/certificate.go",
			`package portal; import "os"; func f() { os.WriteFile("spool/cert/nonce.pem", nil, 0o600) }`),
		plant("portal/audit/spool.go",
			`package audit; import "os"; func f() { os.OpenFile("spool", os.O_APPEND|os.O_WRONLY, 0o600) }`),
		plant("helpers/olivares-portal-power/main.go",
			`package main; import "os/exec"; func main() { exec.Command("systemctl", "reboot") }`),
		plant("base/state.go",
			`package base; import "os"; func f() { os.Rename("state.new", "state") }`),
	}
	mustName := []string{
		plant("helpers/olivares-account-user/user.go", "package main\n\nvar passwordHash []byte\n"),
		plant("portal/audit/record.go", "package audit\n\nvar keyring []byte\n"),
	}

	t.Run("the effect scan reads sign-in and the repair console, and nothing else", func(t *testing.T) {
		sites := writeSites(effectSources(t, root))
		reported := func(path string) bool {
			return slices.ContainsFunc(sites, func(site string) bool {
				return strings.HasPrefix(site, path+": ")
			})
		}
		for _, path := range mustFind {
			if !reported(path) {
				t.Errorf("a write planted in %s, a file of sign-in or the repair console, was not found: %v", path, sites)
			}
		}
		for _, path := range mayWrite {
			if reported(path) {
				t.Errorf("the effect scan reports a write in %s, which is outside sign-in and the repair console", path)
			}
		}
	})

	t.Run("only request-bound mutable passwords are transient", func(t *testing.T) {
		for _, tc := range []struct {
			name, path, source string
			wantCredential     bool
		}{
			{"borrowed PAM request", "portal/portalpam/stack.go", `package portalpam
				type requestStack struct { password []byte }
				func NewRequestStack(password []byte) *requestStack { return &requestStack{password: password} }
				func (s *requestStack) Start() { defer func() { clear(s.password); s.password = nil }() }`, false},
			{"browser request", "portal/signin.go", `package portal
				func (h *protectedNetwork) signIn() { login, password, err := signInCredentials(nil); defer clear(password); _, _ = login, err }
				func signInCredentials(body any) (string, []byte, error) { var password []byte; return "", password, nil }`, false},
			{"copied PAM initializer", "portal/portalpam/stack.go", `package portalpam
				type requestStack struct { password []byte }
				func NewRequestStack(password []byte) *requestStack { return &requestStack{password: append([]byte(nil), password...)} }`, true},
			{"cloned PAM initializer", "portal/portalpam/stack.go", `package portalpam
				type requestStack struct { password []byte }
				func NewRequestStack(password []byte) *requestStack { return &requestStack{password: bytes.Clone(password)} }`, true},
			{"escaped PAM stack", "portal/portalpam/stack.go", `package portalpam
				type requestStack struct { password []byte }; var retained *requestStack
				func NewRequestStack(password []byte) *requestStack { retained = &requestStack{password: password}; return retained }`, true},
			{"escaped PAM buffer", "portal/portalpam/stack.go", `package portalpam
				type requestStack struct { password []byte }; var retained []byte
				func NewRequestStack(password []byte) *requestStack { retained = password; return &requestStack{password: password} }`, true},
			{"aliased PAM buffer", "portal/portalpam/stack.go", `package portalpam
				type requestStack struct { password []byte }
				func NewRequestStack(password []byte) *requestStack { owned := append([]byte(nil), password...); return &requestStack{password: owned} }`, true},
			{"named escaped PAM result", "portal/portalpam/stack.go", `package portalpam
				type requestStack struct { password []byte }; var retained *requestStack
				func NewRequestStack(password []byte) (result *requestStack) { defer func() { retained = result }(); return &requestStack{password: password} }`, true},
			{"captured PAM buffer", "portal/portalpam/stack.go", `package portalpam
				type requestStack struct { password []byte }; var retained func()
				func NewRequestStack(password []byte) *requestStack { retained = func() { clear(password) }; return &requestStack{password: password} }`, true},
			{"unknown PAM consumer", "portal/portalpam/stack.go", `package portalpam
				type requestStack struct { password []byte }
				func NewRequestStack(password []byte) *requestStack { retain(password); return &requestStack{password: password} }`, true},
			{"PAM global", "portal/portalpam/stack.go", `package portalpam; var password []byte`, true},
			{"browser global", "portal/signin.go", `package portal; var password []byte`, true},
			{"PAM store", "portal/portalpam/stack.go", `package portalpam; type store struct { password []byte }`, true},
			{"browser store", "portal/signin.go", `package portal; type protectedNetwork struct { password []byte }`, true},
			{"borrowed field hash", "portal/portalpam/stack.go", `package portalpam; type requestStack struct { passwordHash []byte }`, true},
			{"request hash", "portal/signin.go", `package portal; func signInCredentials() { var passwordHash []byte; _ = passwordHash }`, true},
			{"immutable PAM password", "portal/portalpam/stack.go", `package portalpam; func NewRequestStack(password string) { _ = password }`, true},
			{"immutable borrowed field", "portal/portalpam/stack.go", `package portalpam; type requestStack struct { password string }`, true},
			{"immutable browser password", "portal/signin.go", `package portal; func signInCredentials() { var password string; _ = password }`, true},
			{"unrelated PAM function", "portal/portalpam/stack.go", `package portalpam; func cached(password []byte) { _ = password }`, true},
			{"unrelated browser function", "portal/signin.go", `package portal; func cached(password []byte) { _ = password }`, true},
			{"foreign file", "portal/audit/signin.go", `package portal; func signInCredentials() { var password []byte; _ = password }`, true},
			{"hashing in request", "portal/portalpam/stack.go", `package portalpam; func NewRequestStack(password []byte) { bcrypt.GenerateFromPassword(password, 1) }`, true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				names := identifiers([]parsed{parse(t, tc.path, tc.source)})
				if got := slices.ContainsFunc(names, credentialNames.MatchString); got != tc.wantCredential {
					t.Fatalf("owned credential detected=%v, want %v: %v", got, tc.wantCredential, names)
				}
			})
		}
	})

	t.Run("the credential-name scan reads the whole layer, helpers included", func(t *testing.T) {
		names := identifiers(layerSources(t, root))
		for _, path := range mustName {
			named := slices.ContainsFunc(names, func(name string) bool {
				ident, ok := strings.CutPrefix(name, path+": ")
				return ok && credentialNames.MatchString(ident)
			})
			if !named {
				t.Errorf("a credential name planted in %s was not found", path)
			}
		}
	})
}
