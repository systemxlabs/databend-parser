// Copyright 2021 Datafuse Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use common_meta_types::SeqV;
use common_meta_types::UpsertKV;
use pretty_assertions::assert_eq;

use crate::sm_v002::leveled_store::map_api::MapApi;
use crate::sm_v002::marked::Marked;
use crate::sm_v002::SMV002;
use crate::state_machine::ExpireKey;

#[test]
fn test_one_level_upsert_get_range() -> anyhow::Result<()> {
    let mut sm = SMV002::default();

    let (prev, result) = sm.upsert_kv(UpsertKV::update("a", b"a0"));
    assert_eq!(prev, None);
    assert_eq!(result, Some(SeqV::new(1, b("a0"))));
    let got = sm.get_kv("a");
    assert_eq!(got, Some(SeqV::new(1, b("a0"))));

    let (prev, result) = sm.upsert_kv(UpsertKV::update("b", b"b0"));
    assert_eq!(prev, None);
    assert_eq!(result, Some(SeqV::new(2, b("b0"))));
    let got = sm.get_kv("b");
    assert_eq!(got, Some(SeqV::new(2, b("b0"))));

    let (prev, result) = sm.upsert_kv(UpsertKV::update("a", b"a00"));
    assert_eq!(prev, Some(SeqV::new(1, b("a0"))));
    assert_eq!(result, Some(SeqV::new(3, b("a00"))));
    let got = sm.get_kv("a");
    assert_eq!(got, Some(SeqV::new(3, b("a00"))));

    // get_kv_ref()

    let got = sm.get_kv_ref("a");
    assert_eq!(got.seq(), 3);
    assert_eq!(got.meta(), None);
    assert_eq!(got.value(), Some(&b("a00")));

    let got = sm.get_kv_ref("x");
    assert_eq!(got.seq(), 0);
    assert_eq!(got.meta(), None);
    assert_eq!(got.value(), None);

    let got = sm.prefix_list_kv("");
    assert_eq!(got, vec![
        (s("a"), SeqV::new(3, b("a00"))),
        (s("b"), SeqV::new(2, b("b0")))
    ]);
    Ok(())
}

#[test]
fn test_two_level_upsert_get_range() -> anyhow::Result<()> {
    // |   a/b(D) c d
    // | a a/b    c

    let mut sm = SMV002::default();

    // internal_seq = 0
    sm.upsert_kv(UpsertKV::update("a", b"a0"));
    sm.upsert_kv(UpsertKV::update("a/b", b"b0"));
    sm.upsert_kv(UpsertKV::update("c", b"c0"));

    sm.top.new_level();

    // internal_seq = 3
    sm.upsert_kv(UpsertKV::delete("a/b"));
    sm.upsert_kv(UpsertKV::update("c", b"c1"));
    sm.upsert_kv(UpsertKV::update("d", b"d1"));

    // get_kv_ref()

    let got = sm.get_kv_ref("a");
    assert_eq!((got.seq(), got.value()), (1u64, Some(&b("a0"))));

    let got = sm.get_kv_ref("b");
    assert_eq!((got.seq(), got.value()), (0, None));

    let got = sm.get_kv_ref("c");
    assert_eq!((got.seq(), got.value()), (4, Some(&b("c1"))));

    let got = sm.get_kv_ref("d");
    assert_eq!((got.seq(), got.value()), (5, Some(&b("d1"))));

    // get_kv()

    assert_eq!(sm.get_kv("a"), Some(SeqV::new(1, b("a0"))));
    assert_eq!(sm.get_kv("b"), None);
    assert_eq!(sm.get_kv("c"), Some(SeqV::new(4, b("c1"))));
    assert_eq!(sm.get_kv("d"), Some(SeqV::new(5, b("d1"))));

    // prefix_list_kv()

    let got = sm.prefix_list_kv("");
    assert_eq!(got, vec![
        (s("a"), SeqV::new(1, b("a0"))),
        (s("c"), SeqV::new(4, b("c1"))),
        (s("d"), SeqV::new(5, b("d1"))),
    ]);

    let got = sm.prefix_list_kv("a");
    assert_eq!(got, vec![(s("a"), SeqV::new(1, b("a0"))),]);
    Ok(())
}

#[test]
fn test_update_expire_index() -> anyhow::Result<()> {
    let mut sm = SMV002::default();

    sm.update_expire_cursor(1);
    assert_eq!(sm.expire_cursor, ExpireKey::new(1, 0));

    sm.update_expire_cursor(2);
    assert_eq!(sm.expire_cursor, ExpireKey::new(2, 0));

    sm.update_expire_cursor(1);
    assert_eq!(
        sm.expire_cursor,
        ExpireKey::new(2, 0),
        "expire cursor can not go back"
    );

    Ok(())
}

/// The subscript is internal_seq:
///
///    | kv             | expire
///    | ---            | ---
/// l1 | a₄       c₃    |               10,1₄ -> ø    15,4₄ -> a  20,3₃ -> c          
/// ------------------------------------------------------------
/// l0 | a₁  b₂         |  5,2₂ -> b    10,1₁ -> a
fn build_sm_with_expire() -> SMV002 {
    let mut sm = SMV002::default();

    sm.upsert_kv(UpsertKV::update("a", b"a0").with_expire_sec(10));
    sm.upsert_kv(UpsertKV::update("b", b"b0").with_expire_sec(5));

    sm.top.new_level();

    sm.upsert_kv(UpsertKV::update("c", b"c0").with_expire_sec(20));
    sm.upsert_kv(UpsertKV::update("a", b"a1").with_expire_sec(15));

    // let x: Vec<(&ExpireKey, &Marked<String>)> =
    //     sm.top.range::<ExpireKey, _>(..).collect::<Vec<_>>();
    // dbg!(x);

    sm
}

#[test]
fn test_internal_expire_index() -> anyhow::Result<()> {
    let sm = build_sm_with_expire();

    // Check internal expire index
    let got = sm.top.range::<ExpireKey, _>(..).collect::<Vec<_>>();
    assert_eq!(got, vec![
        (
            &ExpireKey::new(5_000, 2),
            &Marked::new_normal(2, s("b"), None)
        ),
        (&ExpireKey::new(10_000, 1), &Marked::new_tomb_stone(4)),
        (
            &ExpireKey::new(15_000, 4),
            &Marked::new_normal(4, s("a"), None)
        ),
        (
            &ExpireKey::new(20_000, 3),
            &Marked::new_normal(3, s("c"), None)
        ),
    ]);

    Ok(())
}

#[test]
fn test_list_expire_index() -> anyhow::Result<()> {
    let mut sm = build_sm_with_expire();

    let got = sm.list_expire_index().collect::<Vec<_>>();
    assert_eq!(got, vec![
        (&ExpireKey::new(5000, 2), &s("b")),
        (&ExpireKey::new(15000, 4), &s("a")),
        (&ExpireKey::new(20000, 3), &s("c")),
    ]);

    sm.update_expire_cursor(15000);

    let got = sm.list_expire_index().collect::<Vec<_>>();
    assert_eq!(got, vec![
        (&ExpireKey::new(15000, 4), &s("a")),
        (&ExpireKey::new(20000, 3), &s("c")),
    ]);
    Ok(())
}

#[test]
fn test_inserting_expired_becomes_deleting() -> anyhow::Result<()> {
    let mut sm = build_sm_with_expire();

    sm.update_expire_cursor(15_000);

    // Inserting an expired entry will delete it.
    sm.upsert_kv(UpsertKV::update("a", b"a1").with_expire_sec(10));

    assert_eq!(sm.get_kv("a"), None, "a is expired");

    let got = sm.list_expire_index().collect::<Vec<_>>();
    assert_eq!(got, vec![
        //
        (&ExpireKey::new(20_000, 3), &s("c")),
    ]);

    // Check expire store
    let got = sm.top.range::<ExpireKey, _>(..).collect::<Vec<_>>();
    assert_eq!(got, vec![
        //
        (
            &ExpireKey::new(5_000, 2),
            &Marked::new_normal(2, s("b"), None)
        ),
        (&ExpireKey::new(10_000, 1), &Marked::new_tomb_stone(4)),
        (&ExpireKey::new(15_000, 4), &Marked::new_tomb_stone(5),),
        (
            &ExpireKey::new(20_000, 3),
            &Marked::new_normal(3, s("c"), None)
        ),
    ]);

    Ok(())
}

fn s(x: impl ToString) -> String {
    x.to_string()
}

fn b(x: impl ToString) -> Vec<u8> {
    x.to_string().as_bytes().to_vec()
}