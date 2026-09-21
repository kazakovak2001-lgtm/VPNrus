# B54 field-record tool

Run `python -m unittest discover -s tools/field_validation -p "test_*.py"`, then validate a locally captured record with `python tools/field_validation/record_validator.py record.json`. The tool emits canonical JSON only after validation. It supplements, and does not replace, Android's existing `DiagnosticSanitizer`; raw support bundles, credentials, IP addresses, hostnames, subscriber identifiers, SSIDs, and unrestricted logs must never be committed.

No observation fixture is committed because no Android device was attached during B54 implementation.
