# capa-sbom

Pure-Capa SBOM parsing for the two ISO-blessed formats:
CycloneDX 1.x JSON and SPDX 2.x JSON. Zero capabilities: each
parser is a `(String) -> Result<Document, SbomError>` function.
The caller reads the file (or fetches the bytes) with whatever
authority it already holds and hands this library a plain
string; nothing here can touch the filesystem, the network, or
the clock.

The differentiator is first-class support for the `capa:*`
properties the Capa compiler embeds when it emits an SBOM
(`capa --cyclonedx` / `capa --spdx`): per-function declared
capabilities, transitive reachability, source positions. The
query module answers an auditor's questions ("what does
`load_name` declare?") in one call instead of a hand-rolled
property scan.

## Status

v0.1 (seed library). Covers parsing both formats into one
common model, the lookups and capability queries real consumers
(sbom-watch-style auditors) need, and typed errors for every
failure shape. Out of scope for v0.1: writing/generating SBOMs,
the XML serialisations, VEX/vulnerabilities, full JSON-schema
validation, SPDX tag-value (text) documents, files/snippets
sections, and automatic format detection (the caller knows
which flag produced the file).

## Quick start

```capa
import capa_sbom.model
import capa_sbom.cyclonedx
import capa_sbom.query

fun main(stdio: Stdio, fs: Fs)
    let text = match fs.read("sbom.cdx.json")
        Ok(s)  -> s
        Err(e) -> return stdio.eprintln("read failed: ${e}")
    match parse_cyclonedx(text)
        Err(e)  -> stdio.eprintln(error_message(e))
        Ok(doc) ->
            for f in functions(doc)
                let caps = declared_capabilities(f)
                stdio.println("${f.name}: ${caps.length()} capability(ies)")
```

The full runnable example is [`example.capa`](./example.capa);
it parses the two real compiler-emitted fixtures committed
under [`data/`](./data/) (provenance:
[`data/demo_program.capa`](./data/demo_program.capa)), prints
per-function capability sets for both formats, does a point
lookup, and walks the three typed error shapes. Run it from the
repository root with the parent directory on the module search
path:

```bash
CAPA_PATH=.. capa --run example.capa
```

## Install via capa.toml

```toml
[dependencies.capa_sbom]
git = "https://github.com/nelsonduarte/capa_sbom"
tag = "v0.1.0"
verify_key = "6C1D222D491FB88031E041A536CFB426101AA24B"
```

`capa install` runs `git verify-tag` against your GPG keyring;
import the publisher's key first (see [`SECURITY.md`](SECURITY.md)
for the fingerprint provenance and `gpg --import` instructions).

## API surface

### Model (from `capa_sbom.model`)

```capa
pub type SbomFormat = CycloneDx | Spdx

pub type Property  { name: String, value: String }

pub type Component {
    ref_id: String,       // CycloneDX bom-ref / SPDX SPDXID
    name: String,
    version: String,      // "" if absent
    purl: String,         // "" if absent
    properties: List<Property>
}

pub type Relation {
    from_ref: String,
    kind: String,         // "depends-on" (CycloneDX) or the
    to_ref: String        // SPDX relationshipType verbatim
}

pub type Document {
    format: SbomFormat,
    spec_version: String, // "1.5" / "SPDX-2.3"
    subject: String,      // name of the described thing
    components: List<Component>,
    relations: List<Relation>
}

pub type SbomError =
    InvalidJson(String)   // not JSON at all
    NotSbom(String)       // JSON, but not this document kind
    Malformed(String)     // right kind, wrong shape somewhere
```

Plus `format_name(SbomFormat) -> String`,
`error_message(SbomError) -> String`, and the JSON extraction
helpers the parsers share (`json_string`, `json_array`,
`json_object`, `expect_object`).

### Parsers

- `pub fun parse_cyclonedx(text: String) -> Result<Document, SbomError>`
  (from `capa_sbom.cyclonedx`)
- `pub fun parse_spdx(text: String) -> Result<Document, SbomError>`
  (from `capa_sbom.spdx`)

### Queries (from `capa_sbom.query`)

- `pub fun find_by_name(doc, name) -> Option<Component>`
  (first match in document order; names are **not** unique in
  multi-module programs, so use `find_by_ref` when you need a
  unique key)
- `pub fun find_by_ref(doc, ref_id) -> Option<Component>`
  (lookup by the document-unique CycloneDX bom-ref / SPDX
  SPDXID, the same key `Relation` edges use)
- `pub fun find_by_purl(doc, purl) -> Option<Component>`
  (an empty-string probe never matches)
- `pub fun property_values(c, name) -> List<String>`
- `pub fun first_property(c, name) -> Option<String>`
- `pub fun component_kind(c) -> String`
  (the `capa:kind`: `"function"`, `"builtin-capability"`,
  `"capability"`, or `""` for non-Capa producers)
- `pub fun functions(doc) -> List<Component>`
- `pub fun declared_capabilities(c) -> List<String>`
- `pub fun reachable_capabilities(c) -> List<String>`
- `pub fun capability_map(doc) -> Map<String, List<String>>`
  (keyed by `ref_id`, the unique identifier, not by name)
- `pub type Summary { component_count, function_count,
  functions_with_capabilities, relation_count: Int }`
- `pub fun summarize(doc) -> Summary`

## Parsing rules

One strictness rule, applied uniformly: **lenient about
absence, strict about shape**. A missing optional field becomes
a neutral default (`""`, empty list); a present field with the
wrong JSON type is a `Malformed` error. The three error
variants split cleanly:

| Variant | Meaning | Example trigger |
|---|---|---|
| `InvalidJson` | the text is not JSON | truncated file |
| `NotSbom` | valid JSON, wrong document kind | missing `bomFormat`, array root |
| `Malformed` | right kind, wrong shape | `"components": 7` |

Capa's `parse_json` is strict RFC 8259 with cross-backend
parity (control characters, large strings, unicode escapes,
trailing data, number grammar, constants, nesting depth and
negative zero all behave identically on the Python and Wasm
backends). Two known differences remain, both compiler-side:
the message *inside* `InvalidJson` is worded differently per
backend by design, so match on the variant and do not compare
that text; and scientific-notation number formatting is a
pending compiler TODO, which this library never observes
because everything it lifts from an SBOM is strings, arrays
and objects.

Format-specific notes:

- **CycloneDX**: `bomFormat` must be exactly `"CycloneDX"`.
  Components keep `bom-ref`, `name`, `version`, `purl`, and
  `properties[]`. Each `dependencies[]` entry becomes one
  `Relation` per `dependsOn` target with kind `"depends-on"`.
- **SPDX**: `spdxVersion` must start with `"SPDX-"`. Packages
  keep `SPDXID`, `name`, `versionInfo`, the first
  `externalRefs[]` locator whose `referenceType` is `"purl"`,
  and their annotation comments. An annotation comment of the
  form `name=value` becomes a `Property` (split on the first
  `=`; the value keeps any later `=` characters); comments
  without `=` are prose and are skipped. `relationships[]`
  entries become `Relation`s with the `relationshipType`
  verbatim (`DESCRIBES`, `CONTAINS`, `DEPENDS_ON`, ...).

## The capa:* properties

A Capa-emitted SBOM describes the *inside* of the program: one
component per function, carrying machine-checkable capability
facts derived from the type system (not from heuristic taint
guessing). The properties this library surfaces:

| Property | Meaning |
|---|---|
| `capa:kind` | `function`, `builtin-capability`, `capability` |
| `capa:declared_capability` | one per capability in the signature |
| `capa:transitively_reachable_capability` | one per capability reachable through the call graph |
| `capa:provably_excluded_capability` | capabilities the function provably cannot touch |
| `capa:pos` | `file:line:col` of the declaration |
| `capa:return_type`, `capa:param` | signature facts |
| `capa:has_unsafe`, `capa:is_pub` | `"true"` / `"false"` |

In CycloneDX these live in each component's `properties[]`; in
SPDX the compiler encodes the same pairs as package annotation
comments, and this library decodes them back, so
`declared_capabilities` gives the same answer on either format
of the same program.

## Tests

Three deterministic test programs under [`tests/`](./tests/)
(86 assertions): the real CycloneDX and SPDX fixtures, the
error channel, empty documents, a generic third-party SBOM with
no `capa:*` properties, purl lookups, and SPDX annotation
decoding. From the repository root:

```bash
CAPA_PATH=.. capa --run tests/test_cyclonedx.capa
CAPA_PATH=.. capa --run tests/test_spdx.capa
CAPA_PATH=.. capa --run tests/test_edge_cases.capa
```

Each prints one `ok <name>` line per assertion and a final
`RESULT:` line. All three suites pass with byte-identical
output on both backends (`capa --run` and `capa --wasm --run`);
they assert on error variants rather than the `InvalidJson`
message text, which is the one thing that still differs between
backends (see Parsing rules).

## Audit claim

An SBOM-parsing library is exactly the kind of dependency a
supply-chain attacker wants to own, so this one proves the
empty claim about itself. `capa --manifest` over every module:

```
parse_cyclonedx:          []
parse_spdx:               []
find_by_name:             []
find_by_ref:              []
find_by_purl:             []
property_values:          []
first_property:           []
component_kind:           []
functions:                []
declared_capabilities:    []
reachable_capabilities:   []
capability_map:           []
summarize:                []
json_string / json_array / json_object / expect_object: []
```

0 functions with capabilities, 0 crossing unsafe, in every
module. The only capabilities anywhere in this repository are
in the example and the tests (`Stdio` to print, `Fs` to read
the fixture files), and the example attenuates its `Fs` with
`restrict_to("data/")` before the first read. A program using
capa-sbom declares only the authority its own code needs to
obtain the SBOM text.

## Honest limitations (v0.1)

- **Read-only.** No SBOM generation or mutation; use the Capa
  compiler (or your ecosystem's producer) to emit documents.
- **JSON only.** The XML serialisations of both formats are not
  parsed, nor is SPDX tag-value text.
- **Not a validator.** The parser checks the shapes it lifts
  and nothing more; a document can pass here and still violate
  the full CycloneDX/SPDX JSON schema.
- **No VEX.** CycloneDX `vulnerabilities[]` is ignored in v0.1.
- **First purl wins.** An SPDX package with several `purl`
  external refs keeps only the first.
- **Licenses are not modelled.** Deliberate: capability facts
  are this library's value; license extraction is a different
  library's job.
