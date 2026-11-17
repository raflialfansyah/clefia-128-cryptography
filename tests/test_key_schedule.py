"""Unit tests for CLEFIA-128 key schedule constants, intermediate L, WK, and RK."""

import pytest

from clefia.constants import CON_128, T_128
from clefia.key_schedule import derive_intermediate_l, key_schedule_128


def test_t128_matches_rfc6114_table4() -> None:
    """All 30 values of T_128 must match RFC 6114 Table 4 exactly."""
    expected_t128 = (
        0x428A, 0x2145, 0xC4BA, 0x625D, 0xE536, 0x729B, 0xED55, 0xA2B2,
        0x5159, 0xFCB4, 0x7E5A, 0x3F2D, 0xCB8E, 0x65C7, 0xE6FB, 0xA765,
        0x87AA, 0x43D5, 0xF5F2, 0x7AF9, 0xE964, 0x74B2, 0x3A59, 0xC934,
        0x649A, 0x324D, 0xCD3E, 0x669F, 0xE757, 0xA7B3,
    )
    assert len(T_128) == 30
    assert expected_t128 == T_128


def test_con128_matches_rfc6114_table7() -> None:
    """All 60 values of CON_128 must match RFC 6114 Table 7 exactly."""
    expected_con128 = (
        0xF56B7AEB, 0x994A8A42, 0x96A4BD75, 0xFA854521,
        0x735B768A, 0x1F7ABAC4, 0xD5BC3B45, 0xB99D5D62,
        0x52D73592, 0x3EF636E5, 0xC57A1AC9, 0xA95B9B72,
        0x5AB42554, 0x369555ED, 0x1553BA9A, 0x7972B2A2,
        0xE6B85D4D, 0x8A995951, 0x4B550696, 0x2774B4FC,
        0xC9BB034B, 0xA59A5A7E, 0x88CC81A5, 0xE4ED2D3F,
        0x7C6F68E2, 0x104E8ECB, 0xD2263471, 0xBE07C765,
        0x511A3208, 0x3D3BFBE6, 0x1084B134, 0x7CA565A7,
        0x304BF0AA, 0x5C6AAA87, 0xF4347855, 0x9815D543,
        0x4213141A, 0x2E32F2F5, 0xCD180A0D, 0xA139F97A,
        0x5E852D36, 0x32A464E9, 0xC353169B, 0xAF72B274,
        0x8DB88B4D, 0xE199593A, 0x7ED56D96, 0x12F434C9,
        0xD37B36CB, 0xBF5A9A64, 0x85AC9B65, 0xE98D4D32,
        0x7ADF6582, 0x16FE3ECD, 0xD17E32C1, 0xBD5F9F66,
        0x50B63150, 0x3C9757E7, 0x1052B098, 0x7C73B3A7,
    )
    assert len(CON_128) == 60
    assert expected_con128 == CON_128


def test_key_schedule_128_matches_rfc6114_appendix_b() -> None:
    """Verify intermediate L, WK0..WK3, and all 36 round keys RK0..RK35."""
    key = bytes.fromhex("ffeeddccbbaa99887766554433221100")

    intermediate_l = derive_intermediate_l(key)
    assert intermediate_l == bytes.fromhex("8f89a61b9db9d0f393e65627da0d027e")

    schedule = key_schedule_128(key)
    assert schedule.whitening_keys == (0xFFEEDDCC, 0xBBAA9988, 0x77665544, 0x33221100)
    assert len(schedule.round_keys) == 36
    assert schedule.round_keys == (
        0xF3E6CEF9, 0x8DF75E38, 0x41C06256, 0x640AC51B,
        0x6A27E20A, 0x5A791B90, 0xE8C528DC, 0x00336EA3,
        0x59CD17C4, 0x28565583, 0x312A37CC, 0xC08ABD77,
        0x7E8E7EEC, 0x8BE7E949, 0xD3F463D6, 0xA0AAD6AA,
        0xE75EB039, 0x0D657EB9, 0x018002E2, 0x9117D009,
        0x9F98D11E, 0xBABEE8CF, 0xB0369EFA, 0xD3AAEF0D,
        0x3438F93B, 0xF9CEA4A0, 0x68DF9029, 0xB869B4A7,
        0x24D6406D, 0xE74BC550, 0x41C28193, 0x16DE4795,
        0xA34A20F5, 0x33265D14, 0xB19D0554, 0x5142F434,
    )


def test_key_schedule_rejects_wrong_key_sizes() -> None:
    """CLEFIA-128 key schedule must strictly reject non-16-byte keys."""
    for bad_len in (0, 1, 15, 17, 24, 32):
        with pytest.raises(ValueError):
            key_schedule_128(b"\x00" * bad_len)
        with pytest.raises(ValueError):
            derive_intermediate_l(b"\x00" * bad_len)
