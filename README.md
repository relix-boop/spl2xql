# spl2xql

Translate a practical subset of Splunk SPL into a Cortex XQL draft.

Detection logic rarely changes between SIEMs. The query language, the field
names and a handful of quiet semantic differences do. `spl2xql` handles the
mechanical part of a Splunk to Cortex XSIAM migration and tells you, line by
line, what it could not carry over faithfully.

It produces a **draft for review**, not a finished rule. Every lossy step is
reported as a warning, and commands with no translation stay in the output as
`// UNSUPPORTED` comments so nothing disappears silently.

## Example

```
$ python -m spl2xql -f examples/password_spray.spl --map examples/mapping.json
config timeframe = 1h
| datamodel dataset = okta_sso_raw
| filter xdm.event.outcome = XDM_CONST.OUTCOME_FAILED
| comp count_distinct(xdm.source.user.username) as targeted_users, count() as count by xdm.source.ipv4
| filter targeted_users >= 10
| sort desc targeted_users
warning: Value 'failure' translated to XDM_CONST.OUTCOME_FAILED; verify the enum against your tenant
warning: CIM 'src' can be an IP or a hostname; mapped to xdm.source.ipv4
```

## Install and run

Python 3.9 or later, no dependencies. CI runs on 3.12 and 3.13.

```
pip install .
spl2xql 'index=auth action=failure | stats count by user'
spl2xql -f rule.spl --map mapping.json      # query from a file
spl2xql --mode dataset 'index=a | head 5'   # keep field names, no XDM mapping
spl2xql --json -f rule.spl                  # {"xql": ..., "warnings": [...]}
```

As a library:

```python
from spl2xql import translate
result = translate("index=auth action=failure | stats count by user")
print(result.xql, result.warnings)
```

## What is translated

| SPL | XQL |
| --- | --- |
| base search: `field=value`, `!=`, `<`, `>`, `IN (...)`, `AND`/`OR`/`NOT`, wildcards, `field=*` | `filter` |
| `earliest=` / `latest=` (relative) | `config timeframe` |
| `index=` / `sourcetype=` | `datamodel dataset = ...` through the mapping file |
| `where`, `search`, `regex` | `filter` |
| `stats` | `comp` |
| `eval` | `alter` |
| `fields`, `table` | `fields` |
| `rename` | `alter` + `fields -` |
| `sort`, `head` | `sort`, `limit` |
| `dedup` | `dedup` |
| `top`, `rare` | `comp` + `sort` + `limit` |
| `bin` / `bucket`, `timechart` | `bin` + `comp` |
| `fillnull` | `alter ... coalesce()` |

Functions: `isnull`, `isnotnull`, `like`, `match`, `cidrmatch`, `if`, `case`,
`coalesce`, `lower`, `upper`, `len`, `tostring`, `tonumber`, `round`,
`replace`, `mvcount`, `mvjoin`, `split`, hash functions, and arithmetic.

Aggregations: `count`, `dc`, `estdc`, `sum`, `avg`, `min`, `max`, `median`,
`values`, `list`, `earliest`, `latest`, `first`, `last`, `stdev`, `var`.

## What is not translated

`tstats`, `transaction`, `eventstats`, `streamstats`, `join`, `append`,
`lookup`, `rex`, `spath`, subsearches, macros, `tag=` and `eventtype=`.
These need a design decision, not a syntax swap, so the tool flags them and
leaves them to you.

## Mapping file

Dataset names and some field choices are tenant specific. Override the
defaults with a JSON file:

```json
{
  "datasets": { "sourcetype:okta": "okta_sso_raw", "index:fw": "panw_ngfw_traffic_raw" },
  "fields":   { "dest": "xdm.target.ipv4" },
  "values":   { "xdm.event.outcome": { "blocked": "XDM_CONST.OUTCOME_FAILED" } }
}
```

The default CIM to XDM field map lives in `spl2xql/mappings.py`.

## Status and limitations

- Version 0.1. The translation rules follow the public XQL and XDM
  documentation, and the example query plus the null, regex and case
  behaviour were checked in XQL Search. Run every translated query in your
  own environment before you rely on it.
- Regex backslashes are passed through as written, which is what XQL Search
  expects. Use `--double-backslashes` if your rule deployment path needs
  them doubled.
- XDM enum values and reserved words (which need backticks in XQL) are not
  validated.
- In a correlation rule the time window usually belongs to the rule
  settings, not the query, so review any `config timeframe` line.
- `RESEARCH.md` lists the semantic differences found while building this.

## Tests

```
python -m unittest discover -s tests
```

## License

MIT
