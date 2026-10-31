package admin

import (
	"fmt"

	"embyproxy/internal/validators"
)

func syncExportNodes(data map[string]any) (map[string]map[string]any, error) {
	items, ok := data["nodes"].([]any)
	if !ok {
		return nil, fmt.Errorf("%w: nodes", errInvalidSyncResponse)
	}
	nodes := make(map[string]map[string]any, len(items))
	for _, item := range items {
		node, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%w: node object", errInvalidSyncResponse)
		}
		name, ok := node["name"].(string)
		if !ok || !validators.NameRE.MatchString(name) || nodes[name] != nil {
			return nil, fmt.Errorf("%w: node name", errInvalidSyncResponse)
		}
		nodes[name] = node
	}
	return nodes, nil
}

// acknowledgeSyncImports requires exactly one well-formed acknowledgement for
// every submitted node. Validate the entire batch before recording confirmations;
// a malformed response must never authorize pruning or be reported as success.
func acknowledgeSyncImports(data map[string]any, batch []map[string]any, previous map[string]map[string]any, result *syncTargetResult) error {
	items, ok := data["results"].([]any)
	if !ok || len(items) != len(batch) {
		return fmt.Errorf("%w: import results count", errInvalidSyncResponse)
	}
	expected := make(map[string]bool, len(batch))
	for _, node := range batch {
		expected[node["name"].(string)] = true
	}
	confirmed := []string{}
	failures := []syncImportFailure{}
	for _, raw := range items {
		item, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("%w: import result object", errInvalidSyncResponse)
		}
		name, validName := item["name"].(string)
		success, validStatus := item["ok"].(bool)
		if !validName || !validStatus || !expected[name] {
			return fmt.Errorf("%w: import result name/status", errInvalidSyncResponse)
		}
		delete(expected, name)
		if success {
			confirmed = append(confirmed, name)
		} else {
			message, ok := item["error"].(string)
			if !ok || message == "" {
				return fmt.Errorf("%w: import result error", errInvalidSyncResponse)
			}
			failures = append(failures, syncImportFailure{Name: name, Error: message})
		}
	}
	for _, name := range confirmed {
		if _, exists := previous[name]; exists {
			result.Completed.Updated++
		} else {
			result.Completed.Added++
		}
	}
	result.ImportFailures = append(result.ImportFailures, failures...)
	if len(failures) > 0 {
		return fmt.Errorf("%w: %d", errSyncImportFailed, len(failures))
	}
	return nil
}
