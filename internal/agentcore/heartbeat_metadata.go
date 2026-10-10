package agentcore

func heartbeatMetadata(static map[string]string, sample TelemetrySample) map[string]string {
	metadata := cloneStringMap(static)
	for key, value := range sample.heartbeatMetadata {
		metadata[key] = value
	}
	return metadata
}
