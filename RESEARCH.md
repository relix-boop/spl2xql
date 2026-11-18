# Same detection, two SIEMs: what changes when SPL becomes XQL

Notes from building `spl2xql`. The claim is simple: detection logic ports
between Splunk and Cortex XSIAM almost unchanged, and the risk sits in a
short list of semantic differences that do not raise an error. A translated
rule runs, returns rows, and quietly means something else.

**Method and limits.** Each difference below comes from comparing the
documented behaviour of both languages while writing the translation rules.
Items marked *tested* were also observed in XQL Search; the queries are at
the end so you can reproduce them. Behaviour can differ between versions and
environments, so rerun them on yours. Nothing here was measured on production
detections.

## The scenario

Password spraying: one source fails to log in to many different accounts in
a short window.

Splunk, CIM field names:

```
index=auth action=failure earliest=-1h
| stats dc(user) as targeted_users, count by src
| where targeted_users >= 10
| sort - targeted_users
```

Cortex XSIAM, XDM field names (`spl2xql` output, dataset filled in):

```
config timeframe = 1h
| datamodel dataset = <dataset>
| filter xdm.event.outcome = XDM_CONST.OUTCOME_FAILED
| comp count_distinct(xdm.source.user.username) as targeted_users, count() as count by xdm.source.ipv4
| filter targeted_users >= 10
| sort desc targeted_users
```

Four stages map one to one. The logic survived. The differences are all in
the details below.

## Differences that change results without an error

| # | Area | Splunk | Cortex XQL | Effect on a ported rule |
| - | ---- | ------ | ---------- | ----------------------- |
| 1 | Case sensitivity | `search` matches values case-insensitively; `where` and `eval` compare case-sensitively | Case-insensitive by default; `config case_sensitive = true` changes the whole query | *Tested.* A `where user == "Admin"` filter widens after porting. There is no per-stage switch. |
| 2 | Negation and missing fields | `NOT field=x` also returns events without the field; `field!=x` does not | In a `filter` stage, both `not (field = "x")` and `field != "x"` kept rows where the field was null | *Tested.* `NOT` ports as is. `!=` widens: add `and field != null` to keep the Splunk meaning. Inside `if()` the same comparison on a null evaluated as false, so `filter` and `alter` do not agree. |
| 3 | Normalised outcome | `action` is a free string (`success`, `failure`, `blocked`, ...) | `xdm.event.outcome` is an enum (`XDM_CONST.OUTCOME_SUCCESS`, `OUTCOME_FAILED`, ...) | String values need an explicit mapping. Vendor-specific values such as `blocked` have no automatic target. |
| 4 | Source and destination | CIM `src` / `dest` hold an IP or a hostname, depending on the add-on | Separate fields: `xdm.source.ipv4`, `xdm.source.host.hostname` | Grouping by "source" must pick one, and the right one depends on the log source. |
| 5 | Aggregation column names | `stats dc(user)` creates a column literally named `dc(user)` | `comp` generates its own default name | Later stages that reference the old name break or go empty. Always alias. |
| 6 | Wildcards in equality | `*` is a wildcard in `search`, a literal in `where` | `*` is a wildcard in `=` comparisons | A literal asterisk in a `where` string becomes a pattern. |
| 7 | Regex escaping | Single backslash | Single backslash in XQL Search; a doubled backslash did not match | *Tested* in XQL Search only. Rule content deployed as files or through an API may need doubling, so check the path your rules take. |
| 8 | Sort | Optional direction, default ascending; `sort` caps at 10,000 rows unless told otherwise | Direction is written per field | Mostly cosmetic, but a rule that relied on the implicit cap behaves differently. |
| 9 | Dedup | Keeps the first event in search order | Keeps an arbitrary record unless `by asc|desc <field>` is given | "Latest event per user" logic needs the explicit `by desc _time`. |
| 10 | Multivalue results | `values()` returns a multivalue field | `values()` returns an array | Functions applied afterwards differ (`mvcount` vs `array_length`). |
| 11 | Time window | `earliest` / `latest` in the query, with snap-to (`@h`) | `config timeframe`, rolling; correlation rules set the window in the rule | Snapped windows become rolling windows; schedule and window need to be reviewed together. |

## Constructs with no one-line equivalent

- `tstats` over accelerated data models: there is no direct counterpart, so
  the query is rewritten against the data model and its cost profile changes.
- `transaction`: sessions have to be rebuilt with `comp` (min and max time per
  key) or window functions.
- `eventstats` and `streamstats`: map to `windowcomp`, which is a redesign
  rather than a rename.
- `tag=` and `eventtype=`: Splunk knowledge objects. The equivalent meaning
  lives in XDM fields such as `xdm.event.type`, set by data model rules.
- Lookups: become dataset joins or `in (dataset = ...)` subqueries.

## What this suggests for a migration

1. Port the logic mechanically, then review the eleven items above for each
   rule. That review is short and it is where the real errors are.
2. Decide field mapping once per log source, not per rule (item 4).
3. Add aliases and explicit sort and dedup directions in the source SPL
   before migrating. It costs nothing in Splunk and removes items 5, 8 and 9.
4. Test negation and case-sensitive rules against known-good events first.

## Reproduce the tested items

Regex escaping, case sensitivity, and null handling inside `if()`:

```
config timeframe = 1d | dataset = xdr_data | limit 5
| alter s = "abc123"
| alter n = if(s = "zzz", "x", null)
| alter re_single = if(s ~= "\d+", "match", "no"),
        re_double = if(s ~= "\\d+", "match", "no"),
        ci = if(s = "ABC123", "insensitive", "sensitive"),
        neg_null = if(not (n = "a"), "kept", "dropped"),
        ne_null = if(n != "a", "kept", "dropped")
| fields s, re_single, re_double, ci, neg_null, ne_null
| limit 1
```

Observed: `re_single = match`, `re_double = no`, `ci = insensitive`,
`neg_null = dropped`, `ne_null = dropped`.

Null handling in `filter` (run each and compare the counts):

```
config timeframe = 1d | dataset = xdr_data | limit 100
| alter n = if(agent_hostname = "zzz_none", "x", null)
| filter not (n = "a")          // second run: filter n != "a"
| comp count() as kept
```

Observed: all 100 rows kept in both runs, with `n` null on every row.

The password spraying query in this document also ran unchanged against the
data model.

## Sources

- Cortex XQL reference: [config](https://cortex-docs.paloaltonetworks.com/xql-command-reference-guide/readme/stages/config),
  [filter](https://cortex-docs.paloaltonetworks.com/xql-command-reference-guide/readme/stages/filter),
  [comp](https://cortex-docs.paloaltonetworks.com/xql-command-reference-guide/readme/stages/comp),
  [sort](https://cortex-docs.paloaltonetworks.com/xql-command-reference-guide/readme/stages/sort),
  [dedup](https://cortex-docs.paloaltonetworks.com/xql-command-reference-guide/readme/stages/dedup),
  [functions](https://cortex-docs.paloaltonetworks.com/xql-command-reference-guide/readme/functions/functions-list)
- Cortex XSIAM data model schema: [xdm.event](https://cortex-docs.paloaltonetworks.com/xsiam-data-model-schema/fields/event)
- Splunk Search Reference for the SPL side (search, where, stats, sort, dedup).
