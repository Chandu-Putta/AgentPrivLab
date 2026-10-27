from hypothesis import given, settings
from hypothesis import strategies as st

from agent_privilege.delegation.attenuation import amplification, attenuate
from agent_privilege.gateway.canonicalize import canonical_json, request_hash

ids = st.lists(st.sampled_from([f"acct_{c}{i}" for c in "ab" for i in (1, 2, 3)]), unique=True, max_size=6)
tools = st.lists(st.sampled_from(["get_account", "list_transactions", "transfer_funds", "export_statement"]),
                 unique=True, max_size=4)
cents = st.integers(min_value=0, max_value=10**7)


def money(c: int) -> str:
    return f"{c // 100}.{c % 100:02d}"


@settings(max_examples=200)
@given(st.dictionaries(st.text(min_size=1, max_size=5), st.one_of(st.text(max_size=8), st.integers(), st.none()),
                       max_size=6), st.randoms())
def test_canonical_json_key_order_invariant(d, rnd):
    items = list(d.items())
    rnd.shuffle(items)
    assert canonical_json(dict(items)) == canonical_json(d)


@given(cents, cents)
def test_request_hash_binds_amount(a, b):
    p = lambda x: {"source_id": "s", "destination_id": "d", "amount": money(x), "currency": "USD"}  # noqa: E731
    same = request_hash("transfer_funds", p(a), "t", "agent") == request_hash("transfer_funds", p(b), "t", "agent")
    assert same == (a == b)


@given(st.text(max_size=5), st.text(max_size=5))
def test_request_hash_binds_principal_and_tenant(x, y):
    h = lambda t, p: request_hash("get_account", {"account_id": "a"}, t, p)  # noqa: E731
    assert (h(x, "p") == h(y, "p")) == (x == y)
    assert (h("t", x) == h("t", y)) == (x == y)


@settings(max_examples=300)
@given(tools, ids, ids, cents, tools, ids, ids, cents)
def test_attenuation_never_exceeds_parent(pt, pa, pd, pm, rt, ra, rd, rm):
    parent = {"tools": sorted(pt), "accounts": sorted(pa), "destinations": sorted(pd),
              "max_amount_cents": pm, "max_total_cents": pm}
    req = {"tools": rt, "accounts": ra, "destinations": rd, "max_amount": money(rm)}
    amp = amplification(parent, req)
    exceeds = (not set(rt) <= set(pt)) or (not set(ra) <= set(pa)) or (not set(rd) <= set(pd)) or rm > pm
    assert bool(amp) == exceeds
    if not amp:
        child = attenuate(parent, req)
        assert set(child["tools"]) <= set(pt) and set(child["accounts"]) <= set(pa)
        assert set(child["destinations"]) <= set(pd) and child["max_amount_cents"] <= pm
        # attenuating again with the child's own scopes can never grow it
        again = attenuate(child, {"tools": child["tools"], "accounts": child["accounts"],
                                  "destinations": child["destinations"],
                                  "max_amount": money(child["max_amount_cents"])})
        assert again == child
