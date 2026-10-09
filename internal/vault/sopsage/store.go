package sopsage

// The vault's write side (design/adr/0050 §2). Until 0050 this package
// only ever read the encrypted file -- the binary's relationship with the
// vault was read-only, and rotation was `sops secrets.json` -- and with
// [admin] console_manages = false it still is: nothing outside the
// accounts backend constructs a Store.
//
// The plaintext never touches the disk. The encrypted file is handed to
// `sops decrypt` on standard input and the plaintext read from its
// standard output; the new plaintext is handed to `sops encrypt` the same
// way, and only the ciphertext it prints is written, through a temporary
// file in the same directory and a rename (internal/atomicfile), keeping
// the file's owner and mode. Before that rename the new ciphertext is
// decrypted again and compared, so a file serve could not read is never
// put in place.
//
// No error of this file carries a value: decrypt's stderr reads only
// ciphertext and says why a key did not open it; encrypt's stderr could
// quote what it was given, so it is never repeated.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/bunnyiesart/Gatte/internal/atomicfile"
)

// Store writes the sops-encrypted vault named by its two files. Its
// methods are not safe for concurrent use against the same file: the
// caller (internal/admin) serialises them. A `sops secrets.json` edit made
// by hand at the same moment is not coordinated with; the last rename
// wins.
type Store struct {
	secretsFile string
	ageKeyFile  string
	// sops is the binary, "sops" on PATH by default.
	sops string
}

// NewStore returns the write side of the vault at secretsFile, opened
// with the age identity at ageKeyFile.
func NewStore(secretsFile, ageKeyFile string) *Store {
	return &Store{secretsFile: secretsFile, ageKeyFile: ageKeyFile, sops: "sops"}
}

// String never prints a value; there is none held.
func (s *Store) String() string { return "sopsage.Store{" + s.secretsFile + "}" }

// sopsFilename is what sops is told the document is called, so its format
// and creation rules do not depend on a temporary name.
const sopsFilename = "secrets.json"

// Names lists the names the vault holds, sorted.
func (s *Store) Names(ctx context.Context) ([]string, error) {
	plain, _, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	defer wipe(plain)
	return slices.Sorted(maps.Keys(plain)), nil
}

// Set writes value under name. existed says a value was there before.
// Post-condition: on error the file is as it was.
func (s *Store) Set(ctx context.Context, name string, value []byte) (bool, error) {
	if name == "" || len(value) == 0 {
		return false, errors.New("sopsage: a name and a value are required")
	}
	// The vault must exist: this store edits a vault, it does not create
	// one. Creating it here would leave a root-owned 0600 file serve cannot
	// read, encrypted for the recipient the service account's key file
	// names (found in review); the install makes it (README step 3, the
	// image's first run).
	plain, recipients, err := s.open(ctx)
	if err != nil {
		return false, err
	}
	defer wipe(plain)
	_, existed := plain[name]
	plain[name] = string(value)
	return existed, s.write(ctx, plain, recipients)
}

// Delete removes name. existed false: nothing was there, and the file was
// not rewritten.
func (s *Store) Delete(ctx context.Context, name string) (bool, error) {
	plain, recipients, err := s.open(ctx)
	if err != nil {
		return false, err
	}
	defer wipe(plain)
	if _, ok := plain[name]; !ok {
		return false, nil
	}
	delete(plain, name)
	return true, s.write(ctx, plain, recipients)
}

// open decrypts the vault and reads its age recipients from the file's
// sops metadata, which is not encrypted. A missing file is os.ErrNotExist.
func (s *Store) open(ctx context.Context) (map[string]string, []string, error) {
	if err := requireOwnerOnly(s.ageKeyFile); err != nil {
		return nil, nil, err
	}
	enc, err := os.ReadFile(s.secretsFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("sopsage: the secrets file %s does not exist: %w", s.secretsFile, os.ErrNotExist)
		}
		return nil, nil, fmt.Errorf("sopsage: reading the secrets file: %w", err)
	}
	recipients, err := recipientsOf(enc)
	if err != nil {
		return nil, nil, err
	}
	// The recipients come from the vault's own sops metadata, never from
	// the age identity: that file is the service account's (README, "Who
	// owns what"), and this root process must not encrypt for a recipient
	// the service account chose.
	if len(recipients) == 0 {
		return nil, nil, errors.New("sopsage: the secrets file names no age recipient in its sops metadata; edit it with sops")
	}
	plain, err := s.decryptStdin(ctx, enc)
	if err != nil {
		return nil, nil, err
	}
	return plain, recipients, nil
}

// write encrypts plain for recipients, checks the result decrypts to
// plain, and replaces the file.
func (s *Store) write(ctx context.Context, plain map[string]string, recipients []string) error {
	text, err := json.Marshal(plain)
	if err != nil {
		return errors.New("sopsage: encoding the vault failed")
	}
	defer zero(text)
	cmd := exec.CommandContext(ctx, s.sops, "encrypt", "--age", strings.Join(recipients, ","),
		"--input-type", "json", "--output-type", "json", "--filename-override", sopsFilename)
	cmd.Env = s.env(false)
	// "/" so no .sops.yaml of whatever directory this runs in decides the
	// keys: they are the file's own recipients, named above.
	cmd.Dir = "/"
	cmd.Stdin = bytes.NewReader(text)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		// Not its stderr: it could quote the plaintext it was given.
		return fmt.Errorf("sopsage: sops encrypt failed (%v); its output is not repeated, since it could quote a value. Nothing was written", exitOf(err))
	}
	enc := out.Bytes()
	back, err := s.decryptStdin(ctx, enc)
	if err != nil {
		return fmt.Errorf("sopsage: the new vault does not decrypt with the age identity, so it was not written: %w", err)
	}
	same := maps.Equal(back, plain)
	wipe(back)
	if !same {
		return errors.New("sopsage: the new vault does not decrypt to what was encrypted, so it was not written")
	}
	if err := atomicfile.Replace(s.secretsFile, enc, 0o600); err != nil {
		return fmt.Errorf("sopsage: %w", err)
	}
	return nil
}

// decryptStdin hands enc to `sops decrypt` on standard input and reads the
// flat JSON object it prints.
func (s *Store) decryptStdin(ctx context.Context, enc []byte) (map[string]string, error) {
	cmd := exec.CommandContext(ctx, s.sops, "decrypt", "--input-type", "json", "--output-type", "json", "--filename-override", sopsFilename)
	cmd.Env = s.env(true)
	cmd.Dir = "/"
	cmd.Stdin = bytes.NewReader(enc)
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		// Its stderr read only ciphertext; the first line says why (no
		// key, a MAC mismatch). Bounded, in case it is long.
		line, _, _ := strings.Cut(strings.TrimSpace(stderr.String()), "\n")
		if len(line) > 300 {
			line = line[:300]
		}
		zero(out.Bytes())
		return nil, fmt.Errorf("sopsage: sops decrypt failed (%v): %s", exitOf(err), line)
	}
	defer zero(out.Bytes())
	var plain map[string]string
	if err := json.Unmarshal(out.Bytes(), &plain); err != nil {
		// Not err: json's message can quote the document.
		return nil, errors.New("sopsage: decrypted content is not a flat JSON object of string values")
	}
	if plain == nil {
		plain = map[string]string{}
	}
	return plain, nil
}

func (s *Store) env(withKey bool) []string {
	var env []string
	if withKey {
		env = append(env, "SOPS_AGE_KEY_FILE="+s.ageKeyFile)
	}
	if path, ok := os.LookupEnv("PATH"); ok {
		env = append(env, "PATH="+path)
	}
	return env
}

// sopsMeta is the part of an encrypted file's sops metadata this reads.
type sopsMeta struct {
	Sops struct {
		Age []struct {
			Recipient string `json:"recipient"`
		} `json:"age"`
		KMS     []json.RawMessage `json:"kms"`
		GCPKMS  []json.RawMessage `json:"gcp_kms"`
		AzureKV []json.RawMessage `json:"azure_kv"`
		HCVault []json.RawMessage `json:"hc_vault"`
		PGP     []json.RawMessage `json:"pgp"`
	} `json:"sops"`
}

// recipientsOf is the age recipients the file is encrypted for. A file
// that also names another kind of key is refused: encrypting it again for
// its age recipients only would silently drop whoever holds the others.
func recipientsOf(enc []byte) ([]string, error) {
	var m sopsMeta
	if err := json.Unmarshal(enc, &m); err != nil {
		return nil, errors.New("sopsage: the secrets file is not a sops JSON document")
	}
	if len(m.Sops.KMS)+len(m.Sops.GCPKMS)+len(m.Sops.AzureKV)+len(m.Sops.HCVault)+len(m.Sops.PGP) > 0 {
		return nil, errors.New("sopsage: the secrets file is encrypted for keys other than age as well; rewriting it here would drop them. Edit it with sops")
	}
	var out []string
	for _, a := range m.Sops.Age {
		if r := strings.TrimSpace(a.Recipient); r != "" && !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	return out, nil
}

func exitOf(err error) string {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return fmt.Sprintf("exit status %d", ee.ExitCode())
	}
	return err.Error()
}

// wipe drops the values a map held; the strings themselves are immutable
// and are left to the collector, which is as far as Go allows.
func wipe(m map[string]string) {
	for k := range m {
		delete(m, k)
	}
}
