//! Adversarial and Empirical Stress Verification for Milestone 1:
//! - AesNonce zeroization, transparent layout, and slice conversions under boundary conditions
//! - AuditLog hash computation bit-exact fidelity with legacy SHA-256 oracle, raw/hex equivalence, and chain integrity
//! - Username::from_string and EmailAddress::from_string mutation safety, allocation reuse, and invariant adherence
//! - Backup code swap_remove under single-element edge cases, order preservation, dummy hash immunity, and concurrent multi-threaded races

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chrono::{TimeZone, Utc};
use korgan::domain::entities::{AesNonce, AuditEventStatus, AuditLog, UserMfa};
use korgan::domain::value_objects::{AuditLogId, EmailAddress, RequestId, UserId, Username};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

// ============================================================================
// 1. AesNonce Verification
// ============================================================================

#[test]
fn test_aes_nonce_memory_layout_and_size() {
    assert_eq!(
        std::mem::size_of::<AesNonce>(),
        12,
        "AesNonce must have size exactly 12 bytes"
    );
    assert_eq!(
        std::mem::align_of::<AesNonce>(),
        1,
        "AesNonce must have alignment 1"
    );
    assert_eq!(
        std::mem::size_of::<Option<AesNonce>>(),
        13,
        "Option<AesNonce> size should be 13 bytes without padding overhead"
    );

    let raw: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let nonce = AesNonce::new(raw);
    assert_eq!(nonce.into_inner(), raw);
    assert_eq!(nonce.as_slice(), &raw[..]);
}

#[test]
fn test_aes_nonce_slice_conversions_boundary_conditions() {
    // 0-byte slice (empty)
    let empty: &[u8] = &[];
    let nonce_empty = AesNonce::from(empty);
    assert_eq!(nonce_empty.into_inner(), [0u8; 12]);

    // 1-byte slice
    let one_byte: &[u8] = &[0xFE];
    let nonce_one = AesNonce::from(one_byte);
    assert_eq!(
        nonce_one.into_inner(),
        [0xFE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );

    // 11-byte slice (underflow boundary)
    let eleven: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
    let nonce_eleven = AesNonce::from(eleven);
    assert_eq!(
        nonce_eleven.into_inner(),
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0]
    );

    // 12-byte slice (exact boundary)
    let twelve: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let nonce_twelve = AesNonce::from(twelve);
    assert_eq!(
        nonce_twelve.into_inner(),
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    );

    // 13-byte slice (overflow boundary - 1 extra byte)
    let thirteen: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
    let nonce_thirteen = AesNonce::from(thirteen);
    assert_eq!(
        nonce_thirteen.into_inner(),
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        "13th byte must be safely truncated without panic"
    );

    // 1024-byte slice (stress overflow)
    let large: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
    let nonce_large = AesNonce::from(large.as_slice());
    assert_eq!(
        &nonce_large.into_inner()[..],
        &large[..12],
        "Large slice must be safely truncated to 12 bytes"
    );
}

#[test]
fn test_aes_nonce_vec_conversions_boundary_conditions() {
    // Empty Vec
    let nonce_empty = AesNonce::from(Vec::<u8>::new());
    assert_eq!(nonce_empty.into_inner(), [0u8; 12]);

    // 1-byte Vec
    let nonce_one = AesNonce::from(vec![42]);
    assert_eq!(
        nonce_one.into_inner(),
        [42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );

    // 11-byte Vec
    let nonce_eleven = AesNonce::from((1..=11).collect::<Vec<u8>>());
    assert_eq!(
        nonce_eleven.into_inner(),
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0]
    );

    // 12-byte Vec
    let nonce_twelve = AesNonce::from((1..=12).collect::<Vec<u8>>());
    assert_eq!(
        nonce_twelve.into_inner(),
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    );

    // 256-byte Vec
    let nonce_256 = AesNonce::from(vec![0xFF; 256]);
    assert_eq!(nonce_256.into_inner(), [0xFF; 12]);
}

#[test]
fn test_aes_nonce_accessor_and_deref_invariants() {
    let raw = [10u8, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120];
    let nonce = AesNonce::new(raw);

    assert_eq!(nonce.as_slice(), &raw[..]);
    assert_eq!(nonce.as_ref(), &raw[..]);
    assert_eq!(*nonce, raw);
    assert_eq!(nonce.into_inner(), raw);

    let from_ref = AesNonce::from(&raw);
    assert_eq!(from_ref.into_inner(), raw);
}

#[test]
fn test_aes_nonce_zeroization() {
    let mut raw = [0x5A; 12];
    assert_ne!(raw, [0u8; 12]);

    let mut nonce = AesNonce::new(raw);
    assert_eq!(nonce.into_inner(), [0x5A; 12]);

    // Zeroize raw bytes through .0
    nonce.0.zeroize();
    assert_eq!(
        nonce.into_inner(),
        [0u8; 12],
        "AesNonce.0.zeroize() must securely wipe all 12 bytes to zero"
    );

    raw.zeroize();
    assert_eq!(raw, [0u8; 12]);
}

// ============================================================================
// 2. AuditLog Hash Computation & Bit-Exact Chaining Fidelity
// ============================================================================

/// Legacy reference oracle: the exact pre-M1 implementation of compute_entry_hash.
fn legacy_compute_entry_hash(entry: &AuditLog, prev_hash: Option<&str>) -> String {
    let mut hasher = Sha256::new();

    // Cryptographic domain separator
    hasher.update(b"KORGAN_AUDIT_V1\0");

    // Canonical field slots separated by '|'
    let prev_val = prev_hash.unwrap_or("GENESIS");
    hasher.update(prev_val.as_bytes());
    hasher.update(b"|");

    hasher.update(entry.id.to_string().as_bytes());
    hasher.update(b"|");

    if let Some(uid) = entry.user_id {
        hasher.update(uid.to_string().as_bytes());
    }
    hasher.update(b"|");

    if let Some(ip) = entry.actor_ip {
        hasher.update(ip.to_string().as_bytes());
    }
    hasher.update(b"|");

    if let Some(ref ua) = entry.user_agent {
        hasher.update(ua.as_bytes());
    }
    hasher.update(b"|");

    hasher.update(entry.request_id.to_string().as_bytes());
    hasher.update(b"|");

    hasher.update(entry.event_type.as_bytes());
    hasher.update(b"|");

    hasher.update(entry.event_status.as_str().as_bytes());
    hasher.update(b"|");

    hasher.update(entry.created_at.timestamp().to_string().as_bytes());
    hasher.update(b"|");

    let meta_str = entry.metadata.to_string();
    hasher.update(meta_str.as_bytes());

    let digest = hasher.finalize();
    digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}

#[test]
fn test_audit_log_hash_bit_exact_differential_oracle() {
    let test_cases = [
        // Case 1: Minimal fields with None
        (
            AuditLog::new(
                None,
                None,
                None,
                RequestId::new(),
                "test_event_min",
                AuditEventStatus::Success,
                serde_json::json!({}),
            ),
            None,
        ),
        // Case 2: Minimal with prev_hash
        (
            AuditLog::new(
                None,
                None,
                None,
                RequestId::new(),
                "test_event_min_prev",
                AuditEventStatus::Failure,
                serde_json::json!({}),
            ),
            Some("d3b07384d113edec49eaa6238ad5ff00"),
        ),
        // Case 3: IPv4 and User
        (
            AuditLog::new(
                Some(UserId::new()),
                Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))),
                Some("Mozilla/5.0 (X11; Linux x86_64)".to_string()),
                RequestId::new(),
                "login_success",
                AuditEventStatus::Success,
                serde_json::json!({ "auth_method": "password", "attempt": 1 }),
            ),
            Some("0000000000000000000000000000000000000000000000000000000000000000"),
        ),
        // Case 4: IPv6 address
        (
            AuditLog::new(
                Some(UserId::new()),
                Some(IpAddr::V6(Ipv6Addr::new(
                    0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334,
                ))),
                Some("curl/7.81.0".to_string()),
                RequestId::new(),
                "api_access",
                AuditEventStatus::Success,
                serde_json::json!({ "endpoint": "/api/v1/auth", "nested": { "ok": true } }),
            ),
            None,
        ),
        // Case 5: Complex metadata with escaped characters, unicode, numbers, booleans, null
        (
            AuditLog::new(
                Some(UserId::new()),
                Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                Some("Custom \"Agent\" with 'special' chars \n\r\t".to_string()),
                RequestId::new(),
                "complex_event",
                AuditEventStatus::Failure,
                serde_json::json!({
                    "unicode_key": "Üñîçødé 🚀 test",
                    "numbers": [1, -42, 99.123],
                    "flag": false,
                    "nullable": null,
                    "empty_obj": {},
                    "deep": {
                        "level1": {
                            "level2": "leaf"
                        }
                    }
                }),
            ),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ),
    ];

    for (i, (entry, prev_hash)) in test_cases.iter().enumerate() {
        let legacy = legacy_compute_entry_hash(entry, *prev_hash);
        let modern_str = entry.compute_entry_hash(*prev_hash);
        let modern_hex_bytes = entry.compute_entry_hash_hex(*prev_hash);
        let modern_raw_bytes = entry.compute_entry_hash_raw(*prev_hash);

        // 1. Bit-exact match between legacy oracle and modern compute_entry_hash
        assert_eq!(
            modern_str, legacy,
            "Case {i}: modern compute_entry_hash diverged from legacy oracle!"
        );

        // 2. Exact match between compute_entry_hash_hex and compute_entry_hash
        let hex_str = std::str::from_utf8(&modern_hex_bytes).unwrap();
        assert_eq!(
            hex_str, modern_str,
            "Case {i}: compute_entry_hash_hex diverged from compute_entry_hash!"
        );

        // 3. Exact match between compute_entry_hash_raw and compute_entry_hash_hex
        let raw_hex = modern_raw_bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(
            raw_hex, modern_str,
            "Case {i}: compute_entry_hash_raw hex representation diverged!"
        );
    }
}

#[test]
fn test_audit_log_hash_known_sha256_vector() {
    // Construct deterministic AuditLog with fixed constants
    let fixed_id = AuditLogId::from_uuid(
        uuid::Uuid::parse_str("018e0000-0000-7000-8000-000000000001").unwrap(),
    )
    .unwrap();
    let fixed_uid =
        UserId::from_uuid(uuid::Uuid::parse_str("018e0000-0000-7000-8000-000000000002").unwrap())
            .unwrap();
    let fixed_req = RequestId::from_uuid(
        uuid::Uuid::parse_str("018e0000-0000-7000-8000-000000000003").unwrap(),
    )
    .unwrap();
    let fixed_time = Utc.timestamp_opt(1700000000, 0).unwrap();

    let mut log = AuditLog::new(
        Some(fixed_uid),
        Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        Some("AuditTestClient/1.0".to_string()),
        fixed_req,
        "auth.login",
        AuditEventStatus::Success,
        serde_json::json!({ "action": "verify", "code": 200 }),
    );
    log.id = fixed_id;
    log.created_at = fixed_time;

    let computed_hash = log.compute_entry_hash(Some("GENESIS"));

    // Verify manually constructed expected SHA-256
    let mut manual_hasher = Sha256::new();
    manual_hasher.update(b"KORGAN_AUDIT_V1\0");
    manual_hasher.update(b"GENESIS|");
    manual_hasher.update(b"018e0000-0000-7000-8000-000000000001|");
    manual_hasher.update(b"018e0000-0000-7000-8000-000000000002|");
    manual_hasher.update(b"127.0.0.1|");
    manual_hasher.update(b"AuditTestClient/1.0|");
    manual_hasher.update(b"018e0000-0000-7000-8000-000000000003|");
    manual_hasher.update(b"auth.login|");
    manual_hasher.update(b"success|");
    manual_hasher.update(b"1700000000|");
    manual_hasher.update(b"{\"action\":\"verify\",\"code\":200}");
    let expected_manual = manual_hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    assert_eq!(
        computed_hash, expected_manual,
        "AuditLog hash computation must be bit-exact with the canonical canonical format"
    );
}

#[test]
fn test_audit_log_chain_integrity_and_slice_accessors() {
    let mut entries = Vec::new();
    let mut prev_hash: Option<String> = None;

    // Chain 20 entries sequentially
    for i in 0..20 {
        let mut entry = AuditLog::new(
            Some(UserId::new()),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, (i + 1) as u8))),
            Some(format!("Agent-{i}")),
            RequestId::new(),
            "chain_step",
            AuditEventStatus::Success,
            serde_json::json!({ "index": i }),
        );
        entry.chain_to(prev_hash.as_deref());

        // Zero-copy slice accessors
        assert_eq!(
            entry.prev_hash_bytes(),
            prev_hash.as_deref().map(str::as_bytes)
        );
        assert_eq!(
            entry.entry_hash_bytes(),
            entry.entry_hash.as_deref().map(str::as_bytes)
        );

        // Verify integrity against expected prev_hash
        assert!(
            entry.verify_integrity(prev_hash.as_deref()),
            "Entry {i} must verify its cryptographic integrity"
        );

        prev_hash = entry.entry_hash.clone();
        entries.push(entry);
    }

    // Verify all links in the chain
    for i in 0..entries.len() {
        let expected_prev = if i == 0 {
            None
        } else {
            entries[i - 1].entry_hash.as_deref()
        };
        assert!(entries[i].verify_integrity(expected_prev));
    }

    // Adversarial Tampering: Corrupt entry 5 metadata
    let mut tampered_entry = entries[5].clone();
    tampered_entry.metadata = serde_json::json!({ "index": 5, "injected": true });
    assert!(
        !tampered_entry.verify_integrity(entries[4].entry_hash.as_deref()),
        "Tampered entry must fail integrity verification"
    );

    // Adversarial Tampering: Corrupt entry 5 timestamp
    let mut tampered_ts = entries[5].clone();
    tampered_ts.created_at += chrono::Duration::seconds(1);
    assert!(
        !tampered_ts.verify_integrity(entries[4].entry_hash.as_deref()),
        "Tampered timestamp must fail integrity verification"
    );

    // Adversarial Tampering: Wrong prev_hash
    assert!(
        !entries[5].verify_integrity(Some("wrong_prev_hash_value")),
        "Verification must fail when supplied with mismatched prev_hash"
    );
}

// ============================================================================
// 3. Username & EmailAddress Mutation Safety & Invariant Adherence
// ============================================================================

#[test]
fn test_username_from_string_mutation_and_allocation_reuse() {
    // 1. Allocation reuse on already-trimmed string
    let clean_str = "valid_user_99".to_owned();
    let original_ptr = clean_str.as_ptr();
    let username = Username::from_string(clean_str).unwrap();

    // Verify pointer identity: no new heap allocation was performed!
    assert_eq!(
        username.as_str().as_ptr(),
        original_ptr,
        "Username::from_string must reuse heap allocation for clean strings"
    );

    // 2. Untrimmed string correctly trimmed and validated
    let untrimmed = "   alice_bob   ".to_owned();
    let username_trimmed = Username::from_string(untrimmed).unwrap();
    assert_eq!(username_trimmed.as_str(), "alice_bob");

    // 3. Comprehensive boundary conditions
    let valid_cases = vec![
        "abc",
        "user_name",
        "USER123",
        "a_b_c_d_e_f_g_h_i_j_k_l_m_n_o",  // 29 chars
        "123456789012345678901234567890", // 30 chars
    ];
    for case in valid_cases {
        let from_new = Username::new(case).unwrap();
        let from_str = Username::from_string(case.to_owned()).unwrap();
        assert_eq!(from_new, from_str);
        assert_eq!(from_str.as_str(), case);
    }

    // 4. Invariant violations rejected equally by new and from_string
    let invalid_cases = vec![
        "",                                // empty
        "ab",                              // too short (2 chars)
        "1234567890123456789012345678901", // too long (31 chars)
        "user-name",                       // hyphen forbidden
        "user.name",                       // dot forbidden
        "user@name",                       // at forbidden
        "user name",                       // internal space
        "user\u{200b}name",                // zero-width space
        "user\0name",                      // null byte
        "ümlaut",                          // non-ASCII unicode
        "日本語ユーザー",                  // CJK unicode
        "   ",                             // whitespace only
        "\t\n\r",                          // whitespace only
    ];

    for invalid in invalid_cases {
        let res_new = Username::new(invalid);
        let res_from_str = Username::from_string(invalid.to_owned());
        assert!(
            res_new.is_err(),
            "Username::new('{invalid}') should have failed"
        );
        assert!(
            res_from_str.is_err(),
            "Username::from_string('{invalid}') should have failed"
        );
    }
}

#[test]
fn test_email_address_from_string_mutation_and_invariants() {
    // 1. Lowercase ASCII mutation in-place
    let uppercase_email = "John.Doe+Security@EXAMPLE.COM".to_owned();
    let original_ptr = uppercase_email.as_ptr();
    let email = EmailAddress::from_string(uppercase_email).unwrap();

    // Verify it was converted to lowercase
    assert_eq!(email.as_str(), "john.doe+security@example.com");

    // Verify in-place mutation preserved the heap buffer pointer!
    assert_eq!(
        email.as_str().as_ptr(),
        original_ptr,
        "EmailAddress::from_string must lowercase in-place without reallocation"
    );

    // 2. Untrimmed email
    let untrimmed = "   Admin@System.Local   \n".to_owned();
    let email_trimmed = EmailAddress::from_string(untrimmed).unwrap();
    assert_eq!(email_trimmed.as_str(), "admin@system.local");

    // 3. Equivalence matrix between parse and from_string
    let test_matrix = vec![
        "user@example.com",
        "USER@EXAMPLE.COM",
        "first.last+tag@sub.domain.co.uk",
        "a@b.ce",
        "customer_service@company.org",
    ];

    for case in test_matrix {
        let parsed = EmailAddress::parse(case).unwrap();
        let from_str = EmailAddress::from_string(case.to_owned()).unwrap();
        assert_eq!(parsed, from_str);
        assert_eq!(from_str.as_str(), case.to_ascii_lowercase());
    }

    // 4. Invariant violations rejected equally by parse and from_string
    let invalid_emails = vec![
        "",
        "   ",
        "not-an-email",
        "@missing-local.com",
        "missing-domain@",
        "spaces in@local.com",
        "user@.invalid.com",
        "user@domain..com",
    ];

    for invalid in invalid_emails {
        assert!(
            EmailAddress::parse(invalid).is_err(),
            "EmailAddress::parse('{invalid}') should fail"
        );
        assert!(
            EmailAddress::from_string(invalid.to_owned()).is_err(),
            "EmailAddress::from_string('{invalid}') should fail"
        );
    }

    // 5. Maximum email length boundary (254 chars)
    // RFC 5321 limits local-part to 64 chars, and domain labels to 63 chars each.
    let local = "a".repeat(64);
    let label1 = "b".repeat(61);
    let label2 = "c".repeat(60);
    let label3 = "d".repeat(63);
    let tld = "io";
    let max_email = format!("{local}@{label1}.{label2}.{label3}.{tld}");
    assert_eq!(max_email.len(), 254);
    assert!(EmailAddress::parse(&max_email).is_ok());
    assert!(EmailAddress::from_string(max_email.clone()).is_ok());

    let oversized = format!("a{max_email}");
    assert_eq!(oversized.len(), 255);
    assert!(EmailAddress::parse(&oversized).is_err());
    assert!(EmailAddress::from_string(oversized).is_err());
}

// ============================================================================
// 5. Additional Domain Optimizations: IDs, OAuth, Passkey, User
// ============================================================================

#[test]
fn test_id_newtypes_transparent_simd_alignment() {
    use korgan::domain::value_objects::{MfaCredentialId, PasskeyId, SessionId};
    use uuid::Uuid;

    // All ID types must be exactly 16 bytes and aligned to align_of::<Uuid>() (16 bytes on 64-bit systems)
    assert_eq!(std::mem::size_of::<UserId>(), 16);
    assert_eq!(std::mem::align_of::<UserId>(), std::mem::align_of::<Uuid>());

    assert_eq!(std::mem::size_of::<SessionId>(), 16);
    assert_eq!(
        std::mem::align_of::<SessionId>(),
        std::mem::align_of::<Uuid>()
    );

    assert_eq!(std::mem::size_of::<AuditLogId>(), 16);
    assert_eq!(
        std::mem::align_of::<AuditLogId>(),
        std::mem::align_of::<Uuid>()
    );

    assert_eq!(std::mem::size_of::<RequestId>(), 16);
    assert_eq!(
        std::mem::align_of::<RequestId>(),
        std::mem::align_of::<Uuid>()
    );

    assert_eq!(std::mem::size_of::<PasskeyId>(), 16);
    assert_eq!(
        std::mem::align_of::<PasskeyId>(),
        std::mem::align_of::<Uuid>()
    );

    assert_eq!(std::mem::size_of::<MfaCredentialId>(), 16);
    assert_eq!(
        std::mem::align_of::<MfaCredentialId>(),
        std::mem::align_of::<Uuid>()
    );

    // Accessors inlining & fidelity
    let raw_uuid = Uuid::now_v7();
    let uid = UserId::from_uuid(raw_uuid).unwrap();
    assert_eq!(uid.as_uuid(), raw_uuid);
    assert_eq!(uid.to_uuid(), raw_uuid);
    assert_eq!(uid.as_bytes(), raw_uuid.as_bytes());
    assert_eq!(uid.into_inner(), raw_uuid);
}

#[test]
fn test_oauth_provider_zero_alloc_parsing() {
    use korgan::domain::entities::OAuthProvider;

    assert_eq!(
        OAuthProvider::parse("google").unwrap(),
        OAuthProvider::Google
    );
    assert_eq!(
        OAuthProvider::parse("GOOGLE").unwrap(),
        OAuthProvider::Google
    );
    assert_eq!(
        OAuthProvider::parse("GoOgLe").unwrap(),
        OAuthProvider::Google
    );

    assert_eq!(
        OAuthProvider::parse("github").unwrap(),
        OAuthProvider::GitHub
    );
    assert_eq!(
        OAuthProvider::parse("GITHUB").unwrap(),
        OAuthProvider::GitHub
    );
    assert_eq!(
        OAuthProvider::parse("GitHub").unwrap(),
        OAuthProvider::GitHub
    );

    assert!(OAuthProvider::parse("facebook").is_err());
    assert!(OAuthProvider::parse("googlee").is_err());
    assert!(OAuthProvider::parse("").is_err());
}

#[test]
fn test_passkey_name_trimming_and_default() {
    use korgan::domain::entities::Passkey;

    // 1. Empty string defaults to "Passkey"
    let p1 = Passkey::new(UserId::new(), vec![1, 2, 3], serde_json::json!({}), "");
    assert_eq!(p1.name, "Passkey");

    // 2. Whitespace-only string defaults to "Passkey"
    let p2 = Passkey::new(
        UserId::new(),
        vec![1, 2, 3],
        serde_json::json!({}),
        "   \t\n  ",
    );
    assert_eq!(p2.name, "Passkey");

    // 3. Already trimmed string reuses memory
    let clean_name = "YubiKey 5C NFC".to_owned();
    let ptr = clean_name.as_ptr();
    let p3 = Passkey::new(
        UserId::new(),
        vec![1, 2, 3],
        serde_json::json!({}),
        clean_name,
    );
    assert_eq!(p3.name, "YubiKey 5C NFC");
    assert_eq!(p3.name.as_ptr(), ptr);

    // 4. Untrimmed string trimmed correctly
    let p4 = Passkey::new(
        UserId::new(),
        vec![1, 2, 3],
        serde_json::json!({}),
        "  MacBook Touch ID  ",
    );
    assert_eq!(p4.name, "MacBook Touch ID");
}

#[test]
fn test_user_can_login_and_inlined_predicates() {
    use chrono::Duration;
    use korgan::domain::entities::{AccountStatus, User};
    use korgan::domain::errors::DomainError;

    let now = Utc::now();
    let mut user = User::new(
        EmailAddress::parse("test@example.com").unwrap(),
        Some(Username::new("testuser").unwrap()),
        None,
    );

    // Initially unverified
    assert_eq!(user.status, AccountStatus::Unverified);
    assert!(matches!(
        user.can_login(now),
        Err(DomainError::AccountNotActive {
            status: "unverified"
        })
    ));

    // Verify email -> becomes Active
    user.verify_email(now);
    assert_eq!(user.status, AccountStatus::Active);
    assert!(user.can_login(now).is_ok());

    // Lock account
    user.locked_until = Some(now + Duration::minutes(15));
    assert!(user.is_locked(now));
    assert!(matches!(
        user.can_login(now),
        Err(DomainError::AccountLocked { .. })
    ));

    // Expired lock
    assert!(!user.is_locked(now + Duration::minutes(16)));
    assert!(user.can_login(now + Duration::minutes(16)).is_ok());

    // Suspended
    user.locked_until = None;
    user.ban(now);
    assert_eq!(user.status, AccountStatus::Suspended);
    assert!(matches!(
        user.can_login(now),
        Err(DomainError::AccountNotActive {
            status: "suspended"
        })
    ));

    // Unban
    user.unban(now);
    assert_eq!(user.status, AccountStatus::Active);
    assert!(user.can_login(now).is_ok());
}

// ============================================================================
// 4. UserMfa Backup Code swap_remove Edge Cases & Concurrency
// ============================================================================

#[test]
fn test_backup_code_swap_remove_single_element_edge_case() {
    let user_id = UserId::new();
    let mut mfa = UserMfa::new(
        user_id,
        vec![1, 2, 3],
        [0u8; 12],
        vec!["single_code_hash".to_owned()],
    );

    assert_eq!(mfa.remaining_backup_codes_count(), 1);

    // Consume the single code at index 0 when len == 1
    assert!(
        mfa.consume_backup_code("single_code_hash"),
        "Consuming code at index 0 with len == 1 must succeed via swap_remove"
    );
    assert_eq!(mfa.remaining_backup_codes_count(), 0);
    assert!(mfa.backup_code_hashes.is_empty());

    // Consuming again from empty list must return false and not panic
    assert!(
        !mfa.consume_backup_code("single_code_hash"),
        "Consuming from empty list must return false"
    );
    assert_eq!(mfa.remaining_backup_codes_count(), 0);
}

#[test]
fn test_backup_code_swap_remove_empty_list() {
    let user_id = UserId::new();
    let mut mfa = UserMfa::new(user_id, vec![1, 2, 3], [0u8; 12], Vec::new());

    assert_eq!(mfa.remaining_backup_codes_count(), 0);
    assert!(!mfa.consume_backup_code("any_hash"));
    assert_eq!(mfa.remaining_backup_codes_count(), 0);
}

#[test]
fn test_backup_code_swap_remove_ordering_and_drain() {
    let user_id = UserId::new();
    let initial_codes = vec![
        "code_0".to_owned(),
        "code_1".to_owned(),
        "code_2".to_owned(),
        "code_3".to_owned(),
        "code_4".to_owned(),
    ];
    let mut mfa = UserMfa::new(user_id, vec![1, 2, 3], [0u8; 12], initial_codes);

    // Consume code_0 (index 0) -> swap_remove moves code_4 to index 0
    assert!(mfa.consume_backup_code("code_0"));
    assert_eq!(mfa.remaining_backup_codes_count(), 4);
    assert_eq!(mfa.backup_code_hashes[0], "code_4");

    // Consume code_2 (index 2) -> swap_remove moves code_3 to index 2
    assert!(mfa.consume_backup_code("code_2"));
    assert_eq!(mfa.remaining_backup_codes_count(), 3);
    assert_eq!(mfa.backup_code_hashes[2], "code_3");

    // Consume code_4 (now at index 0)
    assert!(mfa.consume_backup_code("code_4"));
    assert_eq!(mfa.remaining_backup_codes_count(), 2);

    // Consume remaining codes
    assert!(mfa.consume_backup_code("code_1"));
    assert_eq!(mfa.remaining_backup_codes_count(), 1);
    assert!(mfa.consume_backup_code("code_3"));
    assert_eq!(mfa.remaining_backup_codes_count(), 0);

    // All codes consumed
    assert!(!mfa.consume_backup_code("code_0"));
    assert!(!mfa.consume_backup_code("code_4"));
}

#[test]
fn test_backup_code_dummy_hash_immunity() {
    let dummy_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    let user_id = UserId::new();

    // Create MFA with 2 legitimate codes
    let mut mfa = UserMfa::new(
        user_id,
        vec![1, 2, 3],
        [0u8; 12],
        vec!["real_code_1".to_owned(), "real_code_2".to_owned()],
    );

    // Even though indices 2..10 evaluate DUMMY_BACKUP_HASH, passing dummy_hash must NOT match!
    assert!(
        !mfa.consume_backup_code(dummy_hash),
        "DUMMY_BACKUP_HASH must never be consumed as a valid code"
    );
    assert_eq!(
        mfa.remaining_backup_codes_count(),
        2,
        "No backup code should have been removed"
    );
}

#[test]
fn test_backup_code_swap_remove_concurrent_stress() {
    let user_id = UserId::new();
    let codes: Vec<String> = (0..10).map(|i| format!("hash_code_{i:02}")).collect();
    let mfa = Arc::new(Mutex::new(UserMfa::new(
        user_id,
        vec![1, 2, 3],
        [0u8; 12],
        codes.clone(),
    )));

    let success_count = Arc::new(AtomicUsize::new(0));
    let failure_count = Arc::new(AtomicUsize::new(0));

    // Spawn 20 concurrent threads:
    // 10 threads attempt to consume valid codes (0..10)
    // 10 threads attempt to consume bogus or duplicate codes
    let mut handles = Vec::new();

    for i in 0..20 {
        let mfa_clone = Arc::clone(&mfa);
        let successes = Arc::clone(&success_count);
        let failures = Arc::clone(&failure_count);
        let code_to_try = if i < 10 {
            format!("hash_code_{i:02}")
        } else {
            // Half bogus, half attempting to re-consume code 0..5
            if i % 2 == 0 {
                format!("bogus_code_{i}")
            } else {
                format!("hash_code_{:02}", i - 10)
            }
        };

        handles.push(std::thread::spawn(move || {
            let mut guard = mfa_clone.lock().unwrap();
            let consumed = guard.consume_backup_code(&code_to_try);
            if consumed {
                successes.fetch_add(1, Ordering::SeqCst);
            } else {
                failures.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }

    // Exactly 10 codes were valid, so exactly 10 successes and 10 failures
    assert_eq!(
        success_count.load(Ordering::SeqCst),
        10,
        "Exactly 10 valid codes should be consumed concurrently"
    );
    assert_eq!(
        failure_count.load(Ordering::SeqCst),
        10,
        "Exactly 10 invalid attempts should fail"
    );

    let guard = mfa.lock().unwrap();
    assert_eq!(
        guard.remaining_backup_codes_count(),
        0,
        "All backup codes should be consumed"
    );
}

#[test]
fn test_backup_code_concurrent_race_on_single_element() {
    let user_id = UserId::new();
    let mfa = Arc::new(Mutex::new(UserMfa::new(
        user_id,
        vec![1, 2, 3],
        [0u8; 12],
        vec!["sole_remaining_code".to_owned()],
    )));

    let success_count = Arc::new(AtomicUsize::new(0));
    let failure_count = Arc::new(AtomicUsize::new(0));

    // 25 threads all race simultaneously to consume the exact same sole remaining code
    let mut handles = Vec::new();
    for _ in 0..25 {
        let mfa_clone = Arc::clone(&mfa);
        let successes = Arc::clone(&success_count);
        let failures = Arc::clone(&failure_count);

        handles.push(std::thread::spawn(move || {
            let mut guard = mfa_clone.lock().unwrap();
            if guard.consume_backup_code("sole_remaining_code") {
                successes.fetch_add(1, Ordering::SeqCst);
            } else {
                failures.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }

    // Exactly 1 thread must succeed, and 24 must fail
    assert_eq!(
        success_count.load(Ordering::SeqCst),
        1,
        "Exactly ONE thread must succeed in consuming the single code (no double-spend!)"
    );
    assert_eq!(
        failure_count.load(Ordering::SeqCst),
        24,
        "24 racing threads must receive false"
    );

    let guard = mfa.lock().unwrap();
    assert_eq!(
        guard.remaining_backup_codes_count(),
        0,
        "Remaining backup codes must be 0"
    );
}
