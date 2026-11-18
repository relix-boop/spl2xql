import unittest

from spl2xql import translate


def xql(spl, **kw):
    return translate(spl, **kw).xql.split("\n")


class BaseSearch(unittest.TestCase):
    def test_fields_time_and_dataset(self):
        out = xql("index=auth sourcetype=okta user=bob earliest=-24h",
                  mapping={"datasets": {"sourcetype:okta": "okta_sso_raw"}})
        self.assertEqual(out, [
            "config timeframe = 24h",
            "| datamodel dataset = okta_sso_raw",
            '| filter xdm.source.user.username = "bob"',
        ])

    def test_missing_dataset_is_flagged(self):
        r = translate("index=auth user=bob")
        self.assertIn("datamodel dataset = <dataset>", r.xql)
        self.assertTrue(any("No dataset mapping" in w for w in r.warnings))

    def test_boolean_logic_and_wildcards(self):
        out = xql("index=a (user=adm* OR user=svc*) NOT src_ip=10.0.0.5 dest_port>1024")
        self.assertEqual(
            out[-1],
            '| filter (xdm.source.user.username = "adm*" or xdm.source.user.username = "svc*") '
            'and not (xdm.source.ipv4 = "10.0.0.5") and xdm.target.port > 1024')

    def test_in_list_exists_and_free_text(self):
        out = xql('index=a dest_port IN (22, 3389) user=* "mimikatz"')
        self.assertEqual(
            out[-1],
            "| filter xdm.target.port in (22, 3389) and xdm.source.user.username != null "
            'and _raw_log contains "mimikatz"')

    def test_enum_value_translation(self):
        out = xql("index=a action=failure")
        self.assertEqual(out[-1], "| filter xdm.event.outcome = XDM_CONST.OUTCOME_FAILED")

    def test_not_equal_gets_null_guard(self):
        out = xql("index=a user!=bob NOT src_ip=10.0.0.5")
        self.assertEqual(
            out[-1],
            '| filter (xdm.source.user.username != "bob" and xdm.source.user.username != null) '
            'and not (xdm.source.ipv4 = "10.0.0.5")')

    def test_time_range_between(self):
        out = xql("index=a earliest=-7d latest=-1d")
        self.assertEqual(out[0], 'config timeframe between "-7d" and "-1d"')

    def test_dataset_mode_keeps_field_names(self):
        out = xql("index=a user=bob | stats count by src", mode="dataset")
        self.assertEqual(out, ["dataset = <dataset>", '| filter user = "bob"',
                               "| comp count() as count by src"])


class Commands(unittest.TestCase):
    def test_stats(self):
        out = xql("index=a | stats count, dc(user) as users, values(dest_ip) AS ips by src_ip")
        self.assertEqual(
            out[-1],
            "| comp count() as count, count_distinct(xdm.source.user.username) as users, "
            "values(xdm.target.ipv4) as ips by xdm.source.ipv4")

    def test_stats_default_alias_warns(self):
        r = translate("index=a | stats dc(user) by src_ip")
        self.assertIn("as dc_user by", r.xql)
        self.assertTrue(any("dc(user)" in w for w in r.warnings))

    def test_alias_is_not_remapped_later(self):
        out = xql("index=a | stats dc(user) as user by src_ip | where user > 5")
        self.assertEqual(out[-1], "| filter user > 5")

    def test_where_functions(self):
        out = xql('index=a | where isnotnull(user) AND (like(url, "%.ru") OR match(url, "\\d+$"))')
        self.assertEqual(
            out[-1],
            '| filter xdm.source.user.username != null and '
            '(xdm.target.url = "*.ru" or xdm.target.url ~= "\\d+$")')

    def test_eval(self):
        out = xql('index=a | eval kb=bytes_out/1024, who=lower(user)." @ ".src_ip, '
                  'tier=case(kb>100, "big", true(), "small")')
        self.assertEqual(
            out[-1],
            "| alter kb = divide(xdm.source.sent_bytes, 1024), "
            'who = concat(lowercase(xdm.source.user.username), " @ ", xdm.source.ipv4), '
            'tier = if(kb > 100, "big", "small")')

    def test_sort_head_dedup_fields(self):
        out = xql("index=a | sort 5 -bytes_out, user | dedup user src_ip | table user, src_ip | head 3")
        self.assertEqual(out[1:], [
            "| sort desc xdm.source.sent_bytes, asc xdm.source.user.username",
            "| limit 5",
            "| dedup xdm.source.user.username, xdm.source.ipv4",
            "| fields xdm.source.user.username, xdm.source.ipv4",
            "| limit 3",
        ])

    def test_rename(self):
        out = xql("index=a | stats count by src_ip | rename src_ip as attacker | fields attacker")
        self.assertEqual(out[-3:], ["| alter attacker = xdm.source.ipv4",
                                    "| fields - xdm.source.ipv4", "| fields attacker"])

    def test_top(self):
        out = xql("index=a | top limit=5 user")
        self.assertEqual(out[-3:], ["| comp count() as count by xdm.source.user.username",
                                    "| sort desc count", "| limit 5"])

    def test_bin_and_timechart(self):
        self.assertEqual(xql("index=a | bin _time span=5m")[-1], "| bin _time span = 5m")
        out = xql("index=a | timechart span=1h count by user")
        self.assertEqual(out[-2:], ["| bin _time span = 1h",
                                    "| comp count() as count by _time, xdm.source.user.username"])

    def test_regex_and_fillnull(self):
        self.assertEqual(xql('index=a | regex user="^svc_\\w+"')[-1],
                         '| filter xdm.source.user.username ~= "^svc_\\w+"')
        self.assertEqual(xql('index=a | regex user="^svc_\\w+"', double_backslashes=True)[-1],
                         '| filter xdm.source.user.username ~= "^svc_\\\\w+"')
        self.assertEqual(xql("index=a | fillnull value=0 bytes_in")[-1],
                         "| alter xdm.target.sent_bytes = coalesce(xdm.target.sent_bytes, 0)")


class Unsupported(unittest.TestCase):
    def test_unsupported_command_is_kept_as_comment(self):
        r = translate("index=a | transaction user | stats count")
        lines = r.xql.split("\n")
        self.assertIn("// UNSUPPORTED: transaction user", lines)
        self.assertEqual(lines[-1], "| comp count() as count")
        self.assertTrue(any("'transaction' not translated" in w for w in r.warnings))

    def test_tstats(self):
        r = translate("| tstats count from datamodel=Authentication by user")
        self.assertIn("// UNSUPPORTED: tstats", r.xql)

    def test_broken_expression_does_not_crash(self):
        r = translate("index=a | where (user = ")
        self.assertIn("// UNSUPPORTED: where", r.xql)


if __name__ == "__main__":
    unittest.main()
