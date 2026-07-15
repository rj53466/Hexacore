from hexacore.safety import ActionClass, Scope, ScopeValidator


def make_scope(**kw):
    base = dict(
        allow_domains=["*.acme-staging.com", "portal.acme-test.com"],
        allow_cidrs=["10.20.30.0/24", "203.0.113.0/28"],
        deny_list=["10.20.30.5", "prod.acme.com"],
        max_action_class=ActionClass.ACTIVE_SCAN,
    )
    base.update(kw)
    return Scope(**base)


def validator(**kw):
    return ScopeValidator(make_scope(**kw))


# --- allow paths ---------------------------------------------------------

def test_in_scope_subdomain_allowed():
    assert validator().check("https://api.acme-staging.com/login").allowed


def test_apex_domain_via_plain_entry_allowed():
    # portal.acme-test.com entry matches the exact host.
    assert validator().check("portal.acme-test.com").allowed


def test_in_scope_ip_allowed():
    assert validator().check("10.20.30.11").allowed


def test_host_with_port_and_url_forms():
    for t in ("http://api.acme-staging.com:8443/x", "api.acme-staging.com:8443"):
        assert validator().check(t).allowed, t


# --- deny paths (the H1 guarantee) --------------------------------------

def test_out_of_scope_domain_denied():
    d = validator().check("https://evil.example.com")
    assert not d.allowed


def test_out_of_scope_ip_denied():
    assert not validator().check("8.8.8.8").allowed


def test_deny_list_wins_over_allow_domain():
    # prod.acme.com is denied even though it is a normal-looking host.
    assert not validator(allow_domains=["*.acme.com"]).check("prod.acme.com").allowed


def test_deny_list_wins_over_allow_cidr():
    # 10.20.30.5 sits inside the allowed /24 but is explicitly denied.
    assert not validator().check("10.20.30.5").allowed


def test_wildcard_does_not_match_apex():
    # *.acme-staging.com must not match the bare apex acme-staging.com.
    v = ScopeValidator(Scope(allow_domains=["*.acme-staging.com"]))
    assert not v.check("acme-staging.com").allowed
    assert v.check("www.acme-staging.com").allowed


def test_suffix_confusion_denied():
    # notacme-staging.com must not be treated as a subdomain of acme-staging.com.
    assert not validator().check("notacme-staging.com").allowed


def test_metadata_ip_denied_even_if_cidr_broad():
    v = ScopeValidator(Scope(allow_cidrs=["0.0.0.0/0"]))
    assert not v.check("169.254.169.254").allowed


def test_metadata_ip_allowed_only_when_explicit():
    v = ScopeValidator(Scope(allow_cidrs=["169.254.169.254/32"]))
    assert v.check("169.254.169.254").allowed


def test_ipv6_out_of_scope_denied():
    assert not validator().check("[2001:db8::1]:443").allowed


def test_ipv6_in_scope_allowed():
    v = ScopeValidator(Scope(allow_cidrs=["2001:db8::/32"]))
    assert v.check("[2001:db8::1]:443").allowed


def test_idn_homoglyph_denied():
    # A Cyrillic-'a' lookalike host must not match the ascii allowlist.
    assert not validator().check("https://аcme-staging.com").allowed


def test_action_class_ceiling_enforced():
    d = validator().check("api.acme-staging.com", ActionClass.ACTIVE_EXPLOIT)
    assert not d.allowed and "ceiling" in d.reason


def test_empty_target_denied():
    assert not validator().check("").allowed


# --- DNS-rebind guard ----------------------------------------------------

def test_dns_rebind_to_denied_ip_blocked():
    # Host is in scope by domain but resolves to a denied IP -> blocked.
    v = ScopeValidator(make_scope(), resolver=lambda h: ["10.20.30.5"])
    assert not v.check("api.acme-staging.com").allowed


def test_dns_rebind_to_metadata_blocked():
    v = ScopeValidator(make_scope(), resolver=lambda h: ["169.254.169.254"])
    assert not v.check("api.acme-staging.com").allowed


def test_dns_resolution_in_scope_allowed():
    v = ScopeValidator(make_scope(), resolver=lambda h: ["10.20.30.11"])
    assert v.check("api.acme-staging.com").allowed
