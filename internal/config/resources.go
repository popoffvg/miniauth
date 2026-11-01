package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/groups"
)

const envResources = "MINIAUTH_RESOURCES_FILE"

// maxResourcesFile caps the read of the resources file.
const maxResourcesFile = 1 << 20

// resourcesFile is the JSON document of MINIAUTH_RESOURCES_FILE.
type resourcesFile struct {
	Resources []json.RawMessage `json:"resources"`
}

// resourceEntry is one entry of resourcesFile.
type resourceEntry struct {
	Name   access.ResourceName `json:"name"`
	URL    access.ResourceURL  `json:"url"`
	Groups []groups.Name       `json:"groups"`
}

// entryErrors are the errors whose fixed text an entry error may show. Any other error is errEntry:
// a decode error can quote the file, and the file can hold a URL with a secret in it.
var entryErrors = []error{
	access.ErrResourceName,
	access.ErrResourceURL,
	access.ErrHost,
	access.ErrPathPrefix,
	groups.ErrName,
}

var (
	errResourcesRead = errors.New("miniauth: MINIAUTH_RESOURCES_FILE cannot be read")
	errResourcesJSON = errors.New(`miniauth: MINIAUTH_RESOURCES_FILE is not a JSON object with a "resources" array`)
	errEntry         = errors.New(`the entry is not an object with "name", "url", and "groups"`)
	errEntryName     = errors.New(`"name" is missing`)
	errEntryURL      = errors.New(`"url" is missing`)
	errEntryRepeat   = errors.New("the name or the URL repeats an earlier entry")
)

// loadResources reads the file at path. An empty path is no file and no predefined resource.
// An error names the variable and the index of the entry. It MUST NOT include a value from the file.
func loadResources(path string) ([]access.PredefinedResource, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	file, err := os.Open(path) // #nosec G304 -- the operator names the file.
	if err != nil {
		return nil, errResourcesRead
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxResourcesFile+1))
	if err != nil || len(data) > maxResourcesFile {
		return nil, errResourcesRead
	}
	return parseResources(data)
}

// parseResources reads the JSON document of the resources file.
func parseResources(data []byte) ([]access.PredefinedResource, error) {
	var document resourcesFile
	if err := strictDecode(data, &document); err != nil || document.Resources == nil {
		return nil, errResourcesJSON
	}
	entries := make([]access.PredefinedResource, 0, len(document.Resources))
	for i, raw := range document.Resources {
		entry, err := parseEntry(raw)
		if err == nil && slices.ContainsFunc(entries, func(seen access.PredefinedResource) bool {
			return seen.Name == entry.Name || seen.URL == entry.URL
		}) {
			err = errEntryRepeat
		}
		if err != nil {
			return nil, fmt.Errorf("miniauth: %s: resources[%d]: %w", envResources, i, err)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func parseEntry(raw json.RawMessage) (access.PredefinedResource, error) {
	var entry resourceEntry
	if err := strictDecode(raw, &entry); err != nil {
		for _, known := range entryErrors {
			if errors.Is(err, known) {
				return access.PredefinedResource{}, known
			}
		}
		return access.PredefinedResource{}, errEntry
	}
	if entry.Name == (access.ResourceName{}) {
		return access.PredefinedResource{}, errEntryName
	}
	if entry.URL == (access.ResourceURL{}) {
		return access.PredefinedResource{}, errEntryURL
	}
	resource := access.PredefinedResource{Name: entry.Name, URL: entry.URL}
	for _, name := range entry.Groups {
		if !slices.Contains(resource.Groups, name) {
			resource.Groups = append(resource.Groups, name)
		}
	}
	return resource, nil
}

// strictDecode refuses an unknown field and any data after the first JSON value.
func strictDecode(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("miniauth: decode: %w", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errEntry
	}
	return nil
}
