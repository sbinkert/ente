package pkg

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ente/cli/internal"
	"github.com/ente/cli/internal/api"
	"github.com/ente/cli/internal/api/models"
	eCrypto "github.com/ente/cli/internal/crypto"
	"github.com/ente/cli/pkg/model"
	"github.com/ente/cli/utils/encoding"
)

// People (face recognition persons) are stored as user entities of type
// "cgroup". Each entity is gzip-compressed JSON, encrypted with the account's
// cgroup entity key (XChaCha20-Poly1305 secretstream). The entity key itself
// is encrypted with the account's master key (secretbox).
//
// A person references faces by face ID ("<fileID>_<box coordinates>"), which
// is identical for every account that can see the same file and uses the same
// remote ML index. That is what makes copying people between accounts work.
const (
	cgroupEntityType      = "cgroup"
	peopleExportVersion   = 1
	entityDiffLimit       = 500
	maxPersonPlainBytes   = 64 << 20
	peopleImportStateBase = ".imported-to-"
)

type PeopleExport struct {
	Version      int              `json:"version"`
	ExportedAt   string           `json:"exportedAt"`
	SourceUserID int64            `json:"sourceUserID"`
	SourceEmail  string           `json:"sourceEmail"`
	People       []ExportedPerson `json:"people"`
}

type ExportedPerson struct {
	ID        string          `json:"id"`
	UpdatedAt int64           `json:"updatedAt"`
	Data      json.RawMessage `json:"data"`
}

type PeopleImportOptions struct {
	DryRun           bool
	UpdateExisting   bool
	KeepContactLinks bool
	AssumeYes        bool
}

// personSummary holds the fields we report on; everything else in the person
// JSON is passed through untouched.
type personSummary struct {
	Name           string `json:"name"`
	IsHidden       bool   `json:"isHidden"`
	Assigned       []struct {
		ID    string   `json:"id"`
		Faces []string `json:"faces"`
	} `json:"assigned"`
	RejectedFaceIDs []string `json:"rejectedFaceIDs"`
}

func summarize(data json.RawMessage) personSummary {
	var s personSummary
	_ = json.Unmarshal(data, &s)
	return s
}

func (s personSummary) faceCount() int {
	n := 0
	for _, c := range s.Assigned {
		n += len(c.Faces)
	}
	return n
}

func (s personSummary) displayName() string {
	if strings.TrimSpace(s.Name) == "" {
		return "(unnamed)"
	}
	return s.Name
}

func normalizedName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// ExportPeople writes all people of the given photos account, decrypted, to outPath.
func (c *ClICtrl) ExportPeople(email string, outPath string) error {
	ctx, account, secret, err := c.photosAccountContext(email)
	if err != nil {
		return err
	}
	key, err := c.cgroupKey(ctx, account, secret, false)
	if err != nil {
		if api.IsNotFound(err) {
			return fmt.Errorf("account %s has no people yet (no cgroup key on server)", account.Email)
		}
		return err
	}
	people, err := c.fetchPeople(ctx, key)
	if err != nil {
		return err
	}
	export := PeopleExport{
		Version:      peopleExportVersion,
		ExportedAt:   time.Now().UTC().Format(time.RFC3339),
		SourceUserID: account.UserID,
		SourceEmail:  account.Email,
		People:       people,
	}
	out, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return err
	}
	path, err := internal.ResolvePath(outPath)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, out, 0600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}

	clusters, faces, named := 0, 0, 0
	for _, p := range people {
		s := summarize(p.Data)
		clusters += len(s.Assigned)
		faces += s.faceCount()
		if strings.TrimSpace(s.Name) != "" {
			named++
		}
	}
	fmt.Printf("Exported %d people (%d named, %d unnamed/ignored), %d clusters, %d faces\n",
		len(people), named, len(people)-named, clusters, faces)
	fmt.Printf("Written to %s\n", path)
	fmt.Println("WARNING: this file contains your people data UNENCRYPTED. Delete it after importing.")
	return nil
}

// ImportPeople creates the people from an export file in the given photos account.
func (c *ClICtrl) ImportPeople(email string, inPath string, opts PeopleImportOptions) error {
	path, err := internal.ResolvePath(inPath)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	var export PeopleExport
	if err := json.Unmarshal(raw, &export); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	if export.Version != peopleExportVersion {
		return fmt.Errorf("unsupported people export version %d", export.Version)
	}

	ctx, account, secret, err := c.photosAccountContext(email)
	if err != nil {
		return err
	}
	if account.UserID == export.SourceUserID {
		return errors.New("refusing to import people into the account they were exported from")
	}

	// Load the target's existing people. In dry-run mode never create a key.
	var key []byte
	var existing []ExportedPerson
	key, err = c.cgroupKey(ctx, account, secret, false)
	switch {
	case err == nil:
		existing, err = c.fetchPeople(ctx, key)
		if err != nil {
			return err
		}
	case api.IsNotFound(err):
		if !opts.DryRun {
			key, err = c.cgroupKey(ctx, account, secret, true)
			if err != nil {
				return err
			}
		}
	default:
		return err
	}

	existingByID := map[string]ExportedPerson{}
	existingByName := map[string][]ExportedPerson{}
	for _, p := range existing {
		existingByID[p.ID] = p
		if n := normalizedName(summarize(p.Data).Name); n != "" {
			existingByName[n] = append(existingByName[n], p)
		}
	}

	statePath := fmt.Sprintf("%s%s%d.json", path, peopleImportStateBase, account.UserID)
	state := map[string]string{} // source person ID -> target person ID
	if b, readErr := os.ReadFile(statePath); readErr == nil {
		if err := json.Unmarshal(b, &state); err != nil {
			return fmt.Errorf("parse import state %s: %w", statePath, err)
		}
	}

	type action struct {
		src    ExportedPerson
		data   []byte
		target *ExportedPerson // nil => create
		skip   string
	}
	var actions []action
	for _, src := range export.People {
		data, err := prepareImportedPerson(src.Data, opts.KeepContactLinks)
		if err != nil {
			return fmt.Errorf("person %s: %w", src.ID, err)
		}
		a := action{src: src, data: data}
		s := summarize(src.Data)

		var match *ExportedPerson
		matchReason := ""
		if targetID, ok := state[src.ID]; ok {
			if t, ok := existingByID[targetID]; ok {
				match, matchReason = &t, "imported earlier"
			}
		}
		if match == nil {
			if n := normalizedName(s.Name); n != "" {
				switch cands := existingByName[n]; len(cands) {
				case 0:
				case 1:
					match, matchReason = &cands[0], "same name"
				default:
					a.skip = fmt.Sprintf("%d people named %q already exist in target", len(cands), s.Name)
				}
			}
		}
		if match != nil {
			if opts.UpdateExisting {
				a.target = match
			} else {
				a.skip = fmt.Sprintf("already exists in target (%s); use --update-existing to overwrite", matchReason)
			}
		}
		actions = append(actions, a)
	}

	creates, updates, skips := 0, 0, 0
	for _, a := range actions {
		s := summarize(a.src.Data)
		verb := "CREATE"
		switch {
		case a.skip != "":
			verb = "SKIP  "
			skips++
		case a.target != nil:
			verb = "UPDATE"
			updates++
		default:
			creates++
		}
		line := fmt.Sprintf("%s %-30s %3d clusters %6d faces", verb, s.displayName(), len(s.Assigned), s.faceCount())
		if a.skip != "" {
			line += "  (" + a.skip + ")"
		}
		fmt.Println(line)
	}
	fmt.Printf("\nTarget account %s: %d to create, %d to update, %d skipped\n", account.Email, creates, updates, skips)
	if opts.DryRun {
		fmt.Println("Dry run: nothing was changed.")
		return nil
	}
	if creates+updates == 0 {
		return nil
	}
	if !opts.AssumeYes {
		ok, err := internal.ConfirmAction(fmt.Sprintf("Write these people to %s? (y/n)", account.Email))
		if err != nil {
			return err
		}
		if !ok {
			fmt.Println("Aborted.")
			return nil
		}
	}

	saveState := func() error {
		b, err := json.MarshalIndent(state, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(statePath, b, 0600)
	}

	var failures int
	for _, a := range actions {
		if a.skip != "" {
			continue
		}
		name := summarize(a.src.Data).displayName()
		encData, header, err := encryptEntity(a.data, key)
		if err != nil {
			return fmt.Errorf("encrypt %s: %w", name, err)
		}
		var res *models.EntityData
		if a.target != nil {
			res, err = c.Client.UpdateEntity(ctx, cgroupEntityType, a.target.ID, encData, header, a.target.UpdatedAt)
		} else {
			res, err = c.Client.CreateEntity(ctx, cgroupEntityType, encData, header)
		}
		if err != nil {
			failures++
			fmt.Printf("FAILED %s: %v\n", name, err)
			continue
		}
		state[a.src.ID] = res.ID
		if err := saveState(); err != nil {
			return fmt.Errorf("save import state %s: %w", statePath, err)
		}
	}
	fmt.Printf("Done: %d written, %d failed. Import state saved to %s\n", creates+updates-failures, failures, statePath)
	fmt.Println("Open Ente Photos on the target account and let it sync; people appear once its ML index includes the shared files.")
	if failures > 0 {
		return fmt.Errorf("%d people failed to import", failures)
	}
	return nil
}

// prepareImportedPerson passes the person JSON through, optionally removing
// the link to an Ente user (email/userID), which describes a relationship from
// the source account's point of view.
func prepareImportedPerson(data json.RawMessage, keepContactLinks bool) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber() // keep file IDs exact
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("invalid person JSON: %w", err)
	}
	if !keepContactLinks {
		delete(m, "email")
		delete(m, "userID")
	}
	return json.Marshal(m)
}

func (c *ClICtrl) photosAccountContext(email string) (context.Context, model.Account, *model.AccSecretInfo, error) {
	accounts, err := c.GetAccounts(context.Background())
	if err != nil {
		return nil, model.Account{}, nil, err
	}
	for _, acc := range accounts {
		if acc.App == api.AppPhotos && strings.EqualFold(acc.Email, strings.TrimSpace(email)) {
			secret, err := c.KeyHolder.LoadSecrets(acc)
			if err != nil {
				return nil, acc, nil, err
			}
			ctx := c.buildRequestContext(context.Background(), acc, model.Filter{})
			c.Client.AddToken(acc.AccountKey(), base64.URLEncoding.EncodeToString(secret.Token))
			return ctx, acc, secret, nil
		}
	}
	return nil, model.Account{}, nil, fmt.Errorf("no photos account %q found in the CLI; add it with `ente account add`", email)
}

// cgroupKey returns the account's decrypted cgroup entity key. With create=true
// it generates and uploads a new key when the account has none.
func (c *ClICtrl) cgroupKey(ctx context.Context, account model.Account, secret *model.AccSecretInfo, create bool) ([]byte, error) {
	remote, err := c.Client.GetEntityKey(ctx, cgroupEntityType)
	if err == nil {
		key, openErr := eCrypto.SecretBoxOpen(
			encoding.DecodeBase64(remote.EncryptedKey),
			encoding.DecodeBase64(remote.Header),
			secret.MasterKey)
		if openErr != nil {
			return nil, fmt.Errorf("decrypt cgroup key for %s: %w", account.Email, openErr)
		}
		return key, nil
	}
	if !create || !api.IsNotFound(err) {
		return nil, err
	}
	key := eCrypto.NewStreamKey()
	encKey, nonce, err := eCrypto.SecretBoxSeal(key, secret.MasterKey)
	if err != nil {
		return nil, err
	}
	if err := c.Client.CreateEntityKey(ctx, cgroupEntityType,
		base64.StdEncoding.EncodeToString(encKey),
		base64.StdEncoding.EncodeToString(nonce)); err != nil {
		return nil, fmt.Errorf("create cgroup key for %s: %w", account.Email, err)
	}
	fmt.Printf("Created people (cgroup) key for %s\n", account.Email)
	return key, nil
}

// fetchPeople pulls the full cgroup diff and returns the live, decrypted people.
func (c *ClICtrl) fetchPeople(ctx context.Context, key []byte) ([]ExportedPerson, error) {
	latest := map[string]models.EntityData{}
	since := int64(0)
	for {
		page, err := c.Client.GetEntityDiff(ctx, cgroupEntityType, since, entityDiffLimit)
		if err != nil {
			return nil, fmt.Errorf("fetch people: %w", err)
		}
		for _, e := range page {
			if prev, ok := latest[e.ID]; !ok || e.UpdatedAt >= prev.UpdatedAt {
				latest[e.ID] = e
			}
			if e.UpdatedAt > since {
				since = e.UpdatedAt
			}
		}
		if len(page) < entityDiffLimit {
			break
		}
	}
	people := make([]ExportedPerson, 0, len(latest))
	for _, e := range latest {
		if e.IsDeleted || e.EncryptedData == nil || e.Header == nil {
			continue
		}
		plain, err := decryptEntity(*e.EncryptedData, *e.Header, key)
		if err != nil {
			return nil, fmt.Errorf("decrypt person %s: %w", e.ID, err)
		}
		if !json.Valid(plain) {
			return nil, fmt.Errorf("person %s is not valid JSON", e.ID)
		}
		people = append(people, ExportedPerson{ID: e.ID, UpdatedAt: e.UpdatedAt, Data: plain})
	}
	sort.Slice(people, func(i, j int) bool {
		ni, nj := normalizedName(summarize(people[i].Data).Name), normalizedName(summarize(people[j].Data).Name)
		if ni != nj {
			return ni < nj
		}
		return people[i].ID < people[j].ID
	})
	return people, nil
}

func decryptEntity(encData, header string, key []byte) ([]byte, error) {
	_, compressed, err := eCrypto.DecryptChaChaBase64Auth(encData, key, header)
	if err != nil {
		return nil, err
	}
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("gunzip: %w", err)
	}
	defer zr.Close()
	plain, err := io.ReadAll(io.LimitReader(zr, maxPersonPlainBytes+1))
	if err != nil {
		return nil, fmt.Errorf("gunzip: %w", err)
	}
	if len(plain) > maxPersonPlainBytes {
		return nil, errors.New("decompressed person exceeds size limit")
	}
	return plain, nil
}

func encryptEntity(plain []byte, key []byte) (string, string, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(plain); err != nil {
		return "", "", err
	}
	if err := zw.Close(); err != nil {
		return "", "", err
	}
	cipher, header, err := eCrypto.EncryptChaCha20poly1305(buf.Bytes(), key)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(cipher), base64.StdEncoding.EncodeToString(header), nil
}
