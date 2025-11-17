package schema

import (
	"fmt"
	"iter"
	"strconv"
	"strings"

	"github.com/frostyeti/mvps/go/errors"
	"go.yaml.in/yaml/v4"
)

type HostEntry struct {
	Host         string
	Port         *uint
	User         *string
	IdentityFile *string
	Password     *string
	Groups       []string
	Meta         map[string]interface{}
	OS           *OS
	Defaults     string
}

type Hosts struct {
	entries map[string]HostEntry
	keys    []string
}

type HostImports struct {
	Hosts   Hosts
	Imports []string
}

func (hi *HostImports) UnmarshalYAML(node *yaml.Node) error {
	if hi == nil {
		hi = &HostImports{}
	}

	hn := hi

	if node.Kind == yaml.SequenceNode {
		for _, item := range node.Content {
			if item.Kind == yaml.ScalarNode {
				hn.Imports = append(hn.Imports, item.Value)
				continue
			}

			if item.Kind != yaml.MappingNode {
				continue
			}

			var host HostEntry
			if err := item.Decode(&host); err != nil {
				return err
			}

			if host.Host == "" {
				return errors.New("host entry missing host field")
			}

			hn.Hosts.Set(host.Host, &host)
		}

		return nil
	}

	if node.Kind != yaml.MappingNode {
		return errors.New("invalid hosts entry")
	}

	for i := 0; i < len(node.Content); i += 2 {
		keyNode := node.Content[i]
		valNode := node.Content[i+1]

		if keyNode.Kind != yaml.ScalarNode {
			return errors.New("host key must be a string")
		}

		key := keyNode.Value

		if valNode.Kind == yaml.ScalarNode {
			next := &HostEntry{}
			hostname := valNode.Value
			if strings.ContainsRune(valNode.Value, '@') {
				parts := strings.SplitN(valNode.Value, "@", 2)
				next.User = &parts[0]
				hostname = parts[1]
			}

			if strings.ContainsRune(hostname, ':') {
				parts := strings.SplitN(hostname, ":", 2)
				hostname = parts[0]
				if len(parts[1]) > 0 {
					portValue, err := strconv.Atoi(parts[1])
					if err != nil {
						return err
					}
					port := uint(portValue)
					next.Port = &port
				}
			}

			next.Host = hostname
			hn.Hosts.Set(key, next)
			continue
		}

		if valNode.Kind != yaml.MappingNode {
			return errors.New("invalid host entry")
		}

		var host HostEntry
		if err := valNode.Decode(&host); err != nil {
			return err
		}

		if host.Host == "" {
			return errors.New("host entry missing host field for " + key)
		}

		hn.Hosts.Set(key, &host)
	}

	return nil

}

func NewHosts() *Hosts {
	return &Hosts{
		entries: make(map[string]HostEntry),
		keys:    []string{},
	}
}

func NewHostImports() *HostImports {
	return &HostImports{
		Hosts:   Hosts{entries: make(map[string]HostEntry), keys: []string{}},
		Imports: []string{},
	}
}

func (h *Hosts) Replace(map[string]HostEntry) {
	if h == nil {
		h = &Hosts{}
	}

	h.entries = map[string]HostEntry{}
	h.keys = []string{}

	for k, v := range h.entries {
		h.keys = append(h.keys, k)
		h.entries[k] = v
	}
}

func (he *HostEntry) UnmarshalYAML(value *yaml.Node) error {
	if he == nil {
		he = &HostEntry{}
	}

	if value.Kind == yaml.ScalarNode {
		he.Host = value.Value
		return nil
	}

	if value.Kind != yaml.MappingNode {
		return yamlErrorf(*value, "expected yaml scalar or mapping for host entry")
	}

	for i := 0; i < len(value.Content); i += 2 {
		keyNode := value.Content[i]
		valueNode := value.Content[i+1]

		key := keyNode.Value
		switch key {
		case "host":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'host' field")
			}
			he.Host = valueNode.Value
		case "port":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'port' field")
			}
			var port uint
			_, err := fmt.Sscanf(valueNode.Value, "%d", &port)
			if err != nil {
				return yamlErrorf(*valueNode, "invalid port number: %v", err)
			}
			he.Port = &port
		case "user":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'user' field")
			}
			user := valueNode.Value
			he.User = &user
		case "identity":
			fallthrough
		case "identity-file":
			fallthrough
		case "identityfile":
			fallthrough
		case "identityFile":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'identity-file' field")
			}
			identityFile := valueNode.Value
			he.IdentityFile = &identityFile
		case "password":
			fallthrough
		case "pass":
			fallthrough
		case "password-variable":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'password' field")
			}
			password := valueNode.Value
			he.Password = &password
		case "groups":
			if valueNode.Kind != yaml.SequenceNode {
				return yamlErrorf(*valueNode, "expected yaml sequence for 'groups' field")
			}
			groups := make([]string, 0)
			for _, item := range valueNode.Content {
				if item.Kind != yaml.ScalarNode {
					return yamlErrorf(*item, "expected yaml scalar for group item")
				}
				groups = append(groups, item.Value)
			}
			he.Groups = groups
		case "meta":
			if valueNode.Kind != yaml.MappingNode {
				return yamlErrorf(*valueNode, "expected yaml mapping for 'meta' field")
			}
			meta := make(map[string]interface{})
			for j := 0; j < len(valueNode.Content); j += 2 {
				metaKeyNode := valueNode.Content[j]
				metaValueNode := valueNode.Content[j+1]

				if metaKeyNode.Kind != yaml.ScalarNode {
					return yamlErrorf(*metaKeyNode, "expected yaml scalar for meta key")
				}
				metaKey := metaKeyNode.Value

				var metaValue interface{}
				if err := metaValueNode.Decode(&metaValue); err != nil {
					return yamlErrorf(*metaValueNode, "failed to decode meta value: %v", err)
				}

				meta[metaKey] = metaValue
			}
			he.Meta = meta
		case "os":
			var os OS
			if err := valueNode.Decode(&os); err != nil {
				return yamlErrorf(*valueNode, "failed to decode 'os' field: %v", err)
			}
			he.OS = &os
		case "defaults":
			if valueNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*valueNode, "expected yaml scalar for 'defaults' field")
			}
			he.Defaults = valueNode.Value
		default:
			return yamlErrorf(*keyNode, "unexpected field '%s' in host entry", key)
		}
	}

	return nil
}

func (h *Hosts) UnmarshalYAML(value *yaml.Node) error {
	if h == nil {
		h = &Hosts{}
	}

	if h.entries == nil {
		h.entries = map[string]HostEntry{}
	}

	if h.keys == nil {
		h.keys = []string{}
	}

	if value.Kind == yaml.SequenceNode {
		for _, item := range value.Content {
			var he HostEntry
			if err := item.Decode(&he); err != nil {
				return err
			}

			if he.Host == "" {
				return yamlErrorf(*item, "host entry cannot have empty host field")
			}

			if _, exists := h.entries[he.Host]; exists {
				return yamlErrorf(*item, "duplicate host entry for host '%s'", he.Host)
			}

			for _, k := range h.keys {
				if strings.EqualFold(k, he.Host) {
					return yamlErrorf(*item, "duplicate host entry for host '%s'", he.Host)
				}
			}

			h.keys = append(h.keys, he.Host)
			h.entries[he.Host] = he
		}

		return nil
	}

	if value.Kind == yaml.MappingNode {
		for i := 0; i < len(value.Content); i += 2 {
			keyNode := value.Content[i]
			valueNode := value.Content[i+1]

			if keyNode.Kind != yaml.ScalarNode {
				return yamlErrorf(*keyNode, "expected yaml scalar for host key")
			}
			host := keyNode.Value

			var he HostEntry
			he.Host = host
			if err := valueNode.Decode(&he); err != nil {
				return err
			}

			if he.Host == "" {
				return yamlErrorf(*valueNode, "host entry cannot have empty host field")
			}

			if he.Host != host {
				return yamlErrorf(*valueNode, "host field '%s' does not match key '%s'", he.Host, host)
			}

			if _, exists := h.entries[he.Host]; exists {
				return yamlErrorf(*keyNode, "duplicate host entry for host '%s'", he.Host)
			}

			for _, k := range h.keys {
				if strings.EqualFold(k, he.Host) {
					return yamlErrorf(*keyNode, "duplicate host entry for host '%s'", he.Host)
				}
			}

			h.keys = append(h.keys, he.Host)
			h.entries[he.Host] = he
		}

		return nil
	}

	return yamlErrorf(*value, "expected yaml sequence or mapping for hosts")
}

func (h *Hosts) Iter() iter.Seq2[string, HostEntry] {
	return func(yield func(string, HostEntry) bool) {
		if h == nil || h.entries == nil {
			return
		}

		for _, k := range h.keys {
			if !yield(k, h.entries[k]) {
				break
			}
		}
	}
}

func (h *Hosts) IsEmpty() bool {
	if h == nil || h.entries == nil {
		return true
	}

	return len(h.entries) == 0
}

func (h *Hosts) Clear() {
	if h != nil {
		h.entries = map[string]HostEntry{}
		h.keys = []string{}
	}
}

func (h *Hosts) FindAll(groupOrHost string) ([]HostEntry, bool) {
	if h == nil || h.entries == nil {
		return nil, false
	}

	results := make([]HostEntry, 0)
	for _, entry := range h.entries {
		if strings.EqualFold(entry.Host, groupOrHost) {
			results = append(results, entry)
			continue
		}

		for _, g := range entry.Groups {
			if strings.EqualFold(g, groupOrHost) {
				results = append(results, entry)
				break
			}
		}
	}

	if len(results) == 0 {
		return nil, false
	}

	return results, true
}

func (h *Hosts) FindGroup(group string) ([]HostEntry, bool) {
	if h == nil || h.entries == nil {
		return nil, false
	}

	results := make([]HostEntry, 0)
	for _, entry := range h.entries {
		for _, g := range entry.Groups {
			if strings.EqualFold(g, group) {
				results = append(results, entry)
				break
			}
		}
	}

	if len(results) == 0 {
		return nil, false
	}

	return results, true
}

func (h *Hosts) Len() int {
	if h == nil || h.entries == nil {
		return 0
	}

	return len(h.entries)
}

func (h *Hosts) Get(host string) (*HostEntry, bool) {
	if h == nil || h.entries == nil {
		return nil, false
	}

	entry, ok := h.entries[host]
	if ok {
		return &entry, ok
	}

	for _, k := range h.keys {
		if strings.EqualFold(k, host) {
			entry, ok := h.entries[k]
			return &entry, ok
		}
	}

	return nil, false
}

func (h *Hosts) Keys() []string {
	if h == nil || h.entries == nil {
		return []string{}
	}

	return h.keys
}

func (h *Hosts) Entries() map[string]HostEntry {
	if h == nil || h.entries == nil {
		return map[string]HostEntry{}
	}

	return h.entries
}

func (h *Hosts) Add(entry *HostEntry) bool {
	if h == nil {
		h = &Hosts{}
	}

	if h.entries == nil {
		h.entries = map[string]HostEntry{}
	}

	_, exists := h.entries[entry.Host]
	if exists {
		return false
	}

	for _, k := range h.keys {
		if strings.EqualFold(k, entry.Host) {
			return false
		}
	}

	h.keys = append(h.keys, entry.Host)
	h.entries[entry.Host] = *entry
	return true
}

func (h *Hosts) Has(host string) bool {
	if h == nil || h.entries == nil {
		return false
	}
	_, exists := h.entries[host]
	if exists {
		return true
	}

	for _, k := range h.keys {
		if strings.EqualFold(k, host) {
			return true
		}
	}

	return false
}

func (h *Hosts) GetAt(index int) (*HostEntry, bool) {
	if h == nil || h.entries == nil {
		return nil, false
	}

	if index < 0 || index >= len(h.keys) {
		return nil, false
	}

	host := h.keys[index]
	entry, ok := h.entries[host]
	return &entry, ok
}

func (h *Hosts) SetAt(index int, entry *HostEntry) {
	if h == nil {
		h = &Hosts{}
	}

	if h.entries == nil {
		h.entries = map[string]HostEntry{}
	}

	if index < 0 || index >= len(h.keys) {
		return
	}

	oldHost := h.keys[index]
	delete(h.entries, oldHost)

	h.keys[index] = entry.Host
	h.entries[entry.Host] = *entry
}

func (h *Hosts) Set(host string, entry *HostEntry) {
	if h == nil {
		h = &Hosts{}
	}

	if h.entries == nil {
		h.entries = map[string]HostEntry{}
	}

	if _, exists := h.entries[host]; !exists {
		h.keys = append(h.keys, host)
	}

	h.entries[host] = *entry
}

func (h *Hosts) Delete(host string) bool {
	if h == nil || h.entries == nil {
		return false
	}

	if _, exists := h.entries[host]; exists {
		delete(h.entries, host)

		for i, k := range h.keys {
			if k == host {
				h.keys = append(h.keys[:i], h.keys[i+1:]...)
				break
			}
		}

		return true
	}

	return false
}
