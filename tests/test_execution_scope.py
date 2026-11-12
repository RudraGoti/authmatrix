import ipaddress

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.rrset
import pytest

from authmatrix.execution_scope import (
    AddressClass,
    AddressPolicyError,
    DnspythonResolver,
    ResolutionError,
    ResolvedAddressSet,
    classify_address,
    validate_address_set,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("8.8.8.8", AddressClass.PUBLIC),
        ("2001:4860:4860::8888", AddressClass.PUBLIC),
        ("10.0.0.1", AddressClass.PRIVATE),
        ("fc00::1", AddressClass.PRIVATE),
        ("127.0.0.1", AddressClass.LOOPBACK),
        ("::1", AddressClass.LOOPBACK),
        ("169.254.1.1", AddressClass.LINK_LOCAL),
        ("fe80::1", AddressClass.LINK_LOCAL),
        ("224.0.0.1", AddressClass.MULTICAST),
        ("ff02::1", AddressClass.MULTICAST),
        ("0.0.0.0", AddressClass.UNSPECIFIED),
        ("::", AddressClass.UNSPECIFIED),
        ("192.0.2.1", AddressClass.SPECIAL),
        ("2001:db8::1", AddressClass.SPECIAL),
        ("240.0.0.1", AddressClass.SPECIAL),
        ("::ffff:192.0.2.1", AddressClass.SPECIAL),
    ],
)
def test_classifies_public_and_restricted_address_ranges(value, expected):
    assert classify_address(value) == expected


def test_address_policy_checks_every_answer_and_exclusions():
    addresses = (
        ipaddress.ip_address("8.8.8.8"),
        ipaddress.ip_address("10.0.0.1"),
    )
    with pytest.raises(AddressPolicyError, match="restricted"):
        validate_address_set(
            ResolvedAddressSet(addresses),
            allow_public_egress=True,
            allowed_restricted_classes=frozenset({AddressClass.PRIVATE}),
            evaluate_ip_scope=lambda _address: (False, False),
        )

    with pytest.raises(AddressPolicyError, match="excluded"):
        validate_address_set(
            ResolvedAddressSet((ipaddress.ip_address("8.8.8.8"),)),
            allow_public_egress=True,
            allowed_restricted_classes=frozenset(),
            evaluate_ip_scope=lambda _address: (False, True),
        )


def test_address_policy_requires_public_egress_and_rejects_non_connectable():
    address = ipaddress.ip_address("8.8.8.8")
    with pytest.raises(AddressPolicyError, match="Public egress"):
        validate_address_set(
            ResolvedAddressSet((address,)),
            allow_public_egress=False,
            allowed_restricted_classes=frozenset(),
            evaluate_ip_scope=lambda _address: (False, False),
        )

    for value in ("224.0.0.1", "0.0.0.0"):
        with pytest.raises(AddressPolicyError, match="non-connectable"):
            validate_address_set(
                ResolvedAddressSet((ipaddress.ip_address(value),)),
                allow_public_egress=True,
                allowed_restricted_classes=frozenset(
                    {AddressClass.MULTICAST, AddressClass.UNSPECIFIED}
                ),
                evaluate_ip_scope=lambda _address: (True, False),
            )


def test_address_policy_requires_complete_nonempty_answer_set():
    for result in (
        ResolvedAddressSet((), complete=True),
        ResolvedAddressSet((ipaddress.ip_address("8.8.8.8"),), False),
    ):
        with pytest.raises(AddressPolicyError):
            validate_address_set(
                result,
                allow_public_egress=True,
                allowed_restricted_classes=frozenset(),
                evaluate_ip_scope=lambda _address: (False, False),
            )


def _reply(query, *records):
    response = dns.message.make_response(query)
    for owner, record_type, value in records:
        response.answer.append(dns.rrset.from_text(owner, 60, "IN", record_type, value))
    return response


def _resolver_with_answers(answer_for, **kwargs):
    def fake_udp(query, nameserver, timeout):
        return answer_for(query)

    return DnspythonResolver(
        nameservers=("127.0.0.1",),
        **kwargs,
    ), fake_udp


def test_injected_dns_transport_resolves_v4_and_v6_without_network(monkeypatch):
    def answer(query):
        name = query.question[0].name.to_text()
        if query.question[0].rdtype == dns.rdatatype.A:
            return _reply(query, (name, "A", "8.8.8.8"))
        return _reply(query, (name, "AAAA", "2001:4860:4860::8888"))

    resolver, fake_udp = _resolver_with_answers(answer)
    monkeypatch.setattr(dns.query, "udp", fake_udp)
    result = resolver.resolve("api.example.com")
    assert result.complete
    assert result.addresses == (
        ipaddress.ip_address("8.8.8.8"),
        ipaddress.ip_address("2001:4860:4860::8888"),
    )


def test_dns_cname_chain_is_bounded_and_loops_are_rejected(monkeypatch):
    def loop_answer(query):
        name = query.question[0].name.to_text()
        target = "b.example." if name == "a.example." else "a.example."
        return _reply(query, (name, "CNAME", target))

    resolver, fake_udp = _resolver_with_answers(
        loop_answer,
        max_cname_depth=3,
    )
    monkeypatch.setattr(dns.query, "udp", fake_udp)
    with pytest.raises(ResolutionError, match="loop"):
        resolver.resolve("a.example")

    def deep_answer(query):
        name = query.question[0].name.to_text()
        label = name.split(".", 1)[0]
        next_name = f"n{int(label[1:]) + 1}.example."
        return _reply(query, (name, "CNAME", next_name))

    resolver, fake_udp = _resolver_with_answers(
        deep_answer,
        max_cname_depth=1,
    )
    monkeypatch.setattr(dns.query, "udp", fake_udp)
    with pytest.raises(ResolutionError, match="depth"):
        resolver.resolve("n0.example")


def test_dns_accepts_bounded_cname_chain_and_rejects_malformed_records(monkeypatch):
    def cname_answer(query):
        name = query.question[0].name.to_text()
        if name == "api.example.com.":
            return _reply(query, (name, "CNAME", "edge.example.net."))
        if query.question[0].rdtype == dns.rdatatype.A:
            return _reply(query, (name, "A", "8.8.4.4"))
        return _reply(query)

    resolver, fake_udp = _resolver_with_answers(cname_answer)
    monkeypatch.setattr(dns.query, "udp", fake_udp)
    assert resolver.resolve("api.example.com").addresses == (
        ipaddress.ip_address("8.8.4.4"),
    )

    def wrong_family(query):
        name = query.question[0].name.to_text()
        if query.question[0].rdtype == dns.rdatatype.A:
            return _reply(query, (name, "AAAA", "2001:4860:4860::8888"))
        return _reply(query)

    resolver, fake_udp = _resolver_with_answers(wrong_family)
    monkeypatch.setattr(dns.query, "udp", fake_udp)
    with pytest.raises(ResolutionError, match="unexpected record"):
        resolver.resolve("api.example.com")


def test_dns_truncation_uses_tcp_and_empty_answers_fail_closed(monkeypatch):
    def truncated_answer(query, nameserver, timeout):
        response = dns.message.make_response(query)
        response.flags |= dns.flags.TC
        return response

    def complete_answer(query, nameserver, timeout):
        name = query.question[0].name.to_text()
        if query.question[0].rdtype == dns.rdatatype.A:
            return _reply(query, (name, "A", "1.1.1.1"))
        return _reply(query)

    resolver = DnspythonResolver(nameservers=("127.0.0.1",))
    monkeypatch.setattr(dns.query, "udp", truncated_answer)
    monkeypatch.setattr(dns.query, "tcp", complete_answer)
    assert resolver.resolve("example.com").addresses == (
        ipaddress.ip_address("1.1.1.1"),
    )

    monkeypatch.setattr(
        dns.query, "udp", lambda query, *_args, **_kwargs: _reply(query)
    )
    with pytest.raises(ResolutionError, match="no A or AAAA"):
        resolver.resolve("example.com")


def test_dns_timeout_and_answer_limit_fail_closed(monkeypatch):
    resolver = DnspythonResolver(nameservers=("127.0.0.1",))

    def timeout(*_args, **_kwargs):
        raise dns.exception.Timeout

    monkeypatch.setattr(dns.query, "udp", timeout)
    with pytest.raises(ResolutionError, match="failed"):
        resolver.resolve("example.com")

    def too_many(query, *_args, **_kwargs):
        name = query.question[0].name.to_text()
        if query.question[0].rdtype == dns.rdatatype.A:
            return _reply(
                query,
                (name, "A", "1.1.1.1"),
                (name, "A", "8.8.8.8"),
            )
        return _reply(query)

    resolver = DnspythonResolver(
        nameservers=("127.0.0.1",),
        max_answers=1,
    )
    monkeypatch.setattr(dns.query, "udp", too_many)
    with pytest.raises(ResolutionError, match="size limit"):
        resolver.resolve("example.com")


def test_server_side_protocol_port_and_resolver_policy_is_validated():
    from authmatrix.execution_scope import (
        InventoryExecutionPolicy,
        load_inventory_execution_policy,
    )

    configured = load_inventory_execution_policy(
        {
            "AUTHMATRIX_INVENTORY_EXECUTION_ENABLED": "true",
            "AUTHMATRIX_INVENTORY_SCHEME": "http",
            "AUTHMATRIX_INVENTORY_PORT": "80",
            "AUTHMATRIX_INVENTORY_ALLOWED_PORTS": "80,443",
            "AUTHMATRIX_INVENTORY_ALLOW_HTTP": "true",
            "AUTHMATRIX_DNS_NAMESERVERS": "192.0.2.53,2001:db8::53",
            "AUTHMATRIX_INVENTORY_RESTRICTED_ADDRESS_CLASSES": "private,link_local",
        }
    )
    assert configured.scheme == "http"
    assert configured.port == 80
    assert configured.dns_nameservers == ("192.0.2.53", "2001:db8::53")
    assert configured.allowed_restricted_classes == frozenset(
        {AddressClass.PRIVATE, AddressClass.LINK_LOCAL}
    )

    with pytest.raises(ValueError, match="allowlisted"):
        InventoryExecutionPolicy(
            enabled=True,
            scheme="https",
            port=8443,
            allowed_ports=frozenset({443}),
            allow_http=False,
            allow_public_egress=True,
            allowed_restricted_classes=frozenset(),
        )
