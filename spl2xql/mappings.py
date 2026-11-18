"""Default mappings. Everything here can be overridden with --map <file.json>.

XDM field names were checked against the public Cortex XSIAM data model
schema guide. CIM field names are ambiguous in places (``src`` and ``dest``
can hold an IP or a hostname), so treat the defaults as a starting point.
"""

# Splunk CIM field -> XDM field
FIELDS = {
    "src": "xdm.source.ipv4",
    "src_ip": "xdm.source.ipv4",
    "src_port": "xdm.source.port",
    "src_host": "xdm.source.host.hostname",
    "src_user": "xdm.source.user.username",
    "user": "xdm.source.user.username",
    "dest": "xdm.target.host.hostname",
    "dest_ip": "xdm.target.ipv4",
    "dest_port": "xdm.target.port",
    "dest_host": "xdm.target.host.hostname",
    "dest_user": "xdm.target.user.username",
    "action": "xdm.event.outcome",
    "reason": "xdm.event.outcome_reason",
    "signature": "xdm.alert.name",
    "signature_id": "xdm.event.id",
    "severity": "xdm.alert.severity",
    "category": "xdm.alert.category",
    "app": "xdm.network.application_protocol",
    "transport": "xdm.network.ip_protocol",
    "protocol": "xdm.network.ip_protocol",
    "process_name": "xdm.source.process.name",
    "process": "xdm.source.process.command_line",
    "process_id": "xdm.source.process.pid",
    "http_user_agent": "xdm.source.user_agent",
    "user_agent": "xdm.source.user_agent",
    "url": "xdm.target.url",
    "bytes_out": "xdm.source.sent_bytes",
    "bytes_in": "xdm.target.sent_bytes",
    "dvc": "xdm.observer.name",
}

# CIM fields whose meaning depends on the source: flagged in the output.
AMBIGUOUS = {
    "src": "CIM 'src' can be an IP or a hostname; mapped to xdm.source.ipv4",
    "dest": "CIM 'dest' can be an IP or a hostname; mapped to xdm.target.host.hostname",
}

# Value translation for enum-like fields: {xdm_field: {spl_value: xql_literal}}
# Literals are emitted as-is (no quotes), so constants work.
VALUES = {
    "xdm.event.outcome": {
        "success": "XDM_CONST.OUTCOME_SUCCESS",
        "failure": "XDM_CONST.OUTCOME_FAILED",
        "failed": "XDM_CONST.OUTCOME_FAILED",
    },
}

# "sourcetype:<name>" or "index:<name>" -> XSIAM dataset. Empty by default:
# dataset names are tenant specific (<vendor>_<product>_raw).
DATASETS = {}

# stats function -> comp function
AGGS = {
    "count": "count", "c": "count",
    "dc": "count_distinct", "distinct_count": "count_distinct",
    "estdc": "approx_count",
    "sum": "sum", "avg": "avg", "mean": "avg",
    "min": "min", "max": "max", "median": "median",
    "values": "values", "list": "list",
    "earliest": "earliest", "latest": "latest",
    "first": "first", "last": "last",
    "stdev": "stddev_sample", "stdevp": "stddev_population", "var": "var",
}

# eval/where function -> XQL function (same argument order)
FUNCS = {
    "if": "if", "coalesce": "coalesce",
    "lower": "lowercase", "upper": "uppercase", "len": "len",
    "trim": "trim", "ltrim": "ltrim", "rtrim": "rtrim",
    "tostring": "to_string", "tonumber": "to_number",
    "round": "round", "floor": "floor", "ceil": "ceil", "ceiling": "ceil",
    "pow": "pow", "sqrt": "sqrt", "exp": "exp", "ln": "ln", "log": "log",
    "min": "least", "max": "greatest",
    "mvcount": "array_length", "mvjoin": "arraystring", "split": "split",
    "replace": "replex",
    "md5": "md5", "sha1": "sha1", "sha256": "sha256", "sha512": "sha512",
    "now": "current_time",
}
