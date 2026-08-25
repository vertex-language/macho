package codesign

// xmlEntitlements wraps a raw entitlements plist (XML) in the 0xfade7171 blob.
// The payload is the verbatim plist bytes the caller supplies.
func xmlEntitlements(plistXML []byte) []byte {
	return genericBlob(csmagicEmbeddedEntitlement, plistXML)
}

// derEntitlements wraps a DER-encoded entitlements dictionary in 0xfade7172.
// macOS 12+ expects DER entitlements alongside the XML slot when entitlements
// are present. derBytes must already be the DER encoding of the dictionary.
func derEntitlements(derBytes []byte) []byte {
	return genericBlob(csmagicDEREntitlement, derBytes)
}