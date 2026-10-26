# Cross-check: run the OFFICIAL `pip install anp` verifier against the exact
# Signature-Input / Signature / Content-Digest + inline DID document that our
# extension signing core produced. True means our wire format is spec-correct.
import json
import sys

from anp.authentication.http_signatures import verify_http_message_signature


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/anp-signed.json"
    data = json.load(open(path))
    ok, msg, details = verify_http_message_signature(
        did_document=data["didDocument"],
        request_method=data["request_method"],
        request_url=data["request_url"],
        headers=data["headers"],
        body=data["body"].encode("utf-8"),
    )
    print(f"official verifier -> {'PASS ✅' if ok else 'FAIL ❌'}")
    print(f"message: {msg}")
    print(f"details: {json.dumps(details)}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
