//! Empirical Challenger Verification Test Suite for Milestone 1:
//! - Memory layout and alignment of newtype IDs and AesNonce
//! - Zero-allocation assertions for AuditLog::verify_integrity and compute_entry_hash_raw/hex
//! - Algorithmic correctness of UserMfa::consume_backup_code under swap_remove permutations
//! - Edge case and boundary stress-testing for Username and EmailAddress

#![allow(
    unsafe_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::mem::{align_of, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use chrono::Utc;
use korgan::domain::entities::audit::{AuditEventStatus, AuditLog, audit_events};
use korgan::domain::entities::mfa::{AesNonce, MAX_BACKUP_CODES, UserMfa};
use korgan::domain::value_objects::{
    AuditLogId, EmailAddress, MAX_EMAIL_LENGTH, MAX_USERNAME_LENGTH, MIN_USERNAME_LENGTH,
    MfaCredentialId, OAuthAccountId, PasskeyId, RequestId, SessionId, TokenFamilyId, UserId,
    Username,
};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Thread-isolated Counting Allocator to empirically verify ZERO heap allocations
// ---------------------------------------------------------------------------

struct CountingAlloc;

thread_local! {
    static TRACKING_ACTIVE: Cell<bool> = const { Cell::new(false) };
    static THREAD_ALLOC_COUNT: Cell<usize> = const { Cell::new(0) };
}

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        TRACKING_ACTIVE.with(|active| {
            if active.get() {
                THREAD_ALLOC_COUNT.with(|count| count.set(count.get() + 1));
            }
        });
        // SAFETY: Delegating directly to the standard System allocator with identical layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: Delegating directly to the standard System allocator with identical ptr and layout.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

fn start_tracking() {
    THREAD_ALLOC_COUNT.with(|count| count.set(0));
    TRACKING_ACTIVE.with(|active| active.set(true));
}

fn stop_and_get_alloc_count() -> usize {
    TRACKING_ACTIVE.with(|active| active.set(false));
    THREAD_ALLOC_COUNT.with(|count| count.get())
}

// ---------------------------------------------------------------------------
// Item 1: Memory Layout and Alignment Verification
// ---------------------------------------------------------------------------

#[test]
fn empirical_verify_ids_memory_layout_and_alignment() {
    // 1. Verify size_of == 16 for all newtype IDs
    assert_eq!(size_of::<UserId>(), 16);
    assert_eq!(size_of::<SessionId>(), 16);
    assert_eq!(size_of::<TokenFamilyId>(), 16);
    assert_eq!(size_of::<AuditLogId>(), 16);
    assert_eq!(size_of::<OAuthAccountId>(), 16);
    assert_eq!(size_of::<PasskeyId>(), 16);
    assert_eq!(size_of::<MfaCredentialId>(), 16);
    assert_eq!(size_of::<RequestId>(), 16);

    // 2. Verify align_of == align_of::<Uuid>()
    let uuid_align = align_of::<Uuid>();
    assert_eq!(align_of::<UserId>(), uuid_align);
    assert_eq!(align_of::<SessionId>(), uuid_align);
    assert_eq!(align_of::<TokenFamilyId>(), uuid_align);
    assert_eq!(align_of::<AuditLogId>(), uuid_align);
    assert_eq!(align_of::<OAuthAccountId>(), uuid_align);
    assert_eq!(align_of::<PasskeyId>(), uuid_align);
    assert_eq!(align_of::<MfaCredentialId>(), uuid_align);
    assert_eq!(align_of::<RequestId>(), uuid_align);

    // 3. Verify #[repr(transparent)] allows transmute between newtype and Uuid
    let raw_uuid = Uuid::now_v7();
    // SAFETY: UserId has #[repr(transparent)] over Uuid.
    let user_id: UserId = unsafe { std::mem::transmute(raw_uuid) };
    assert_eq!(user_id.as_uuid(), raw_uuid);

    // 4. Verify AesNonce memory layout
    assert_eq!(size_of::<AesNonce>(), 12);
    assert_eq!(align_of::<AesNonce>(), 1);
    assert_eq!(size_of::<Option<AesNonce>>(), 13);
    assert_eq!(align_of::<Option<AesNonce>>(), 1);

    // 5. Verify inline array in UserMfa: totp_secret_nonce is [u8; 12]
    let mfa = UserMfa::new(
        UserId::new(),
        vec![1, 2, 3],
        [42u8; 12],
        vec!["code1".to_string()],
    );
    assert_eq!(size_of_val(&mfa.totp_secret_nonce), 12);
}

// ---------------------------------------------------------------------------
// Item 2: Zero-Allocation in AuditLog Integrity Verification
// ---------------------------------------------------------------------------

#[test]
fn empirical_verify_audit_log_zero_allocation_integrity() {
    let user_id = UserId::new();
    let request_id = RequestId::new();
    let ipv4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42));
    let ipv6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

    // Case A: Full entry with IPv4, User Agent, and rich metadata
    let mut entry_v4 = AuditLog::new(
        Some(user_id),
        Some(ipv4),
        Some("Mozilla/5.0 (X11; Linux x86_64)".to_string()),
        request_id,
        audit_events::LOGIN_SUCCESS,
        AuditEventStatus::Success,
        serde_json::json!({
            "method": "password",
            "mfa_used": true,
            "latency_ms": 45,
            "nested": { "tags": ["iam", "audit"], "risk": 0.05 }
        }),
    );
    let prev_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    entry_v4.chain_to(Some(prev_hash));

    // 1. Verify compute_entry_hash_raw does 0 heap allocations
    start_tracking();
    let raw_hash = entry_v4.compute_entry_hash_raw(Some(prev_hash));
    let allocs_raw = stop_and_get_alloc_count();
    assert_eq!(
        allocs_raw, 0,
        "compute_entry_hash_raw allocated {allocs_raw} heap blocks"
    );
    assert_eq!(raw_hash.len(), 32);

    // 2. Verify compute_entry_hash_hex does 0 heap allocations
    start_tracking();
    let hex_hash = entry_v4.compute_entry_hash_hex(Some(prev_hash));
    let allocs_hex = stop_and_get_alloc_count();
    assert_eq!(
        allocs_hex, 0,
        "compute_entry_hash_hex allocated {allocs_hex} heap blocks"
    );
    assert_eq!(hex_hash.len(), 64);

    // 3. Verify verify_integrity does 0 heap allocations
    start_tracking();
    let is_valid = entry_v4.verify_integrity(Some(prev_hash));
    let allocs_verify = stop_and_get_alloc_count();
    assert!(is_valid);
    assert_eq!(
        allocs_verify, 0,
        "verify_integrity allocated {allocs_verify} heap blocks"
    );

    // 4. Verify tampered check does 0 heap allocations
    start_tracking();
    let is_tampered_valid = entry_v4.verify_integrity(Some("tampered_prev_hash"));
    let allocs_tampered = stop_and_get_alloc_count();
    assert!(!is_tampered_valid);
    assert_eq!(
        allocs_tampered, 0,
        "verify_integrity on tampered entry allocated {allocs_tampered} heap blocks"
    );

    // Case B: IPv6 Entry with Genesis (None) prev_hash
    let mut entry_v6 = AuditLog::new(
        None,
        Some(ipv6),
        None,
        request_id,
        audit_events::REGISTER,
        AuditEventStatus::Success,
        serde_json::json!({}),
    );
    entry_v6.chain_to(None);

    start_tracking();
    let is_v6_valid = entry_v6.verify_integrity(None);
    let allocs_v6 = stop_and_get_alloc_count();
    assert!(is_v6_valid);
    assert_eq!(
        allocs_v6, 0,
        "verify_integrity (IPv6, Genesis) allocated {allocs_v6} heap blocks"
    );
}

// ---------------------------------------------------------------------------
// Item 3: Backup Code Invalidation with `swap_remove` (Permutations & Stress)
// ---------------------------------------------------------------------------

#[test]
fn empirical_verify_backup_code_swap_remove_permutations() {
    let user_id = UserId::new();
    let raw_codes: Vec<String> = (0..MAX_BACKUP_CODES)
        .map(|i| format!("backup_hash_{i:02}"))
        .collect();

    let mut mfa = UserMfa::new(user_id, vec![0; 32], [0u8; 12], raw_codes.clone());
    assert_eq!(mfa.remaining_backup_codes_count(), 10);

    // 1. Consume code from the middle (e.g. index 3: "backup_hash_03")
    // swap_remove should swap the last element ("backup_hash_09") into index 3
    let code_to_consume = "backup_hash_03";
    assert!(mfa.consume_backup_code(code_to_consume));
    assert_eq!(mfa.remaining_backup_codes_count(), 9);
    assert_eq!(mfa.backup_code_hashes[3], "backup_hash_09");

    // Cannot consume the same code again
    assert!(!mfa.consume_backup_code(code_to_consume));
    assert_eq!(mfa.remaining_backup_codes_count(), 9);

    // 2. Consume what is now at index 3 ("backup_hash_09")
    // swap_remove should swap the current last element ("backup_hash_08") into index 3
    assert!(mfa.consume_backup_code("backup_hash_09"));
    assert_eq!(mfa.remaining_backup_codes_count(), 8);
    assert_eq!(mfa.backup_code_hashes[3], "backup_hash_08");

    // 3. Consume head (index 0: "backup_hash_00")
    // swap_remove moves current last ("backup_hash_07") to index 0
    assert!(mfa.consume_backup_code("backup_hash_00"));
    assert_eq!(mfa.remaining_backup_codes_count(), 7);
    assert_eq!(mfa.backup_code_hashes[0], "backup_hash_07");

    // 4. Exhaust all remaining codes one by one in arbitrary order
    let remaining_to_consume = vec![
        "backup_hash_08",
        "backup_hash_07",
        "backup_hash_01",
        "backup_hash_02",
        "backup_hash_04",
        "backup_hash_05",
        "backup_hash_06",
    ];

    for code in remaining_to_consume {
        assert!(
            mfa.consume_backup_code(code),
            "Failed to consume remaining code {code}"
        );
    }

    assert_eq!(mfa.remaining_backup_codes_count(), 0);

    // Cannot consume any code from empty list
    assert!(!mfa.consume_backup_code("backup_hash_01"));
    assert!(!mfa.consume_backup_code("random_code"));
    assert_eq!(mfa.remaining_backup_codes_count(), 0);

    // 5. Regenerate codes and verify single element swap_remove (len == 1)
    let now = Utc::now();
    mfa.regenerate_backup_codes(vec!["single_code".to_string()], now);
    assert_eq!(mfa.remaining_backup_codes_count(), 1);
    assert!(mfa.consume_backup_code("single_code"));
    assert_eq!(mfa.remaining_backup_codes_count(), 0);
    assert!(!mfa.consume_backup_code("single_code"));
}

// ---------------------------------------------------------------------------
// Item 4: Username and EmailAddress Edge Cases & Boundary Stress
// ---------------------------------------------------------------------------

#[test]
fn empirical_verify_username_edge_cases() {
    // Length boundary constants
    assert_eq!(MIN_USERNAME_LENGTH, 3);
    assert_eq!(MAX_USERNAME_LENGTH, 30);

    // Empty string
    assert!(Username::new("").is_err());
    assert!(Username::from_string(String::new()).is_err());

    // Whitespace only
    assert!(Username::new("   ").is_err());
    assert!(Username::from_string("   ".to_string()).is_err());
    assert!(Username::new("\t\n\r").is_err());

    // Too short (2 characters)
    assert!(Username::new("ab").is_err());
    assert!(Username::from_string("ab".to_string()).is_err());

    // Min valid length (3 characters)
    let min_u = Username::new("abc").unwrap();
    assert_eq!(min_u.as_str(), "abc");
    let min_from_str = Username::from_string("abc".to_string()).unwrap();
    assert_eq!(min_from_str.as_str(), "abc");

    // Max valid length (30 characters)
    let max_str_30 = "a".repeat(30);
    let max_u = Username::new(&max_str_30).unwrap();
    assert_eq!(max_u.as_str(), max_str_30);
    let max_from_str = Username::from_string(max_str_30.clone()).unwrap();
    assert_eq!(max_from_str.as_str(), max_str_30);

    // Exceeding max length (31 characters)
    let max_str_31 = "a".repeat(31);
    assert!(Username::new(&max_str_31).is_err());
    assert!(Username::from_string(max_str_31).is_err());

    // Character set constraints: alphanumeric and underscore allowed
    let valid_charset = "Valid_User_123";
    let u_valid = Username::new(valid_charset).unwrap();
    assert_eq!(u_valid.as_str(), valid_charset);

    // Disallowed ASCII characters
    for illegal in ["user-name", "user.name", "user@domain", "user#1", "user!"] {
        assert!(
            Username::new(illegal).is_err(),
            "Expected '{illegal}' to be rejected"
        );
        assert!(
            Username::from_string(illegal.to_string()).is_err(),
            "Expected from_string('{illegal}') to be rejected"
        );
    }

    // Unicode vs ASCII: non-ASCII characters MUST be rejected
    for unicode_str in [
        "юзернейм",                 // Cyrillic
        "alíce",                    // Accented letter
        "user_🦀",                  // Emoji
        "admin\u{200b}",            // Zero-width space
        "\u{0430}\u{0431}\u{0432}", // Russian abc
    ] {
        assert!(
            Username::new(unicode_str).is_err(),
            "Expected '{unicode_str}' to be rejected"
        );
        assert!(
            Username::from_string(unicode_str.to_string()).is_err(),
            "Expected from_string('{unicode_str}') to be rejected"
        );
    }

    // Leading and trailing whitespace handling
    let padded = "   alice_99   ";
    let trimmed_u = Username::new(padded).unwrap();
    assert_eq!(trimmed_u.as_str(), "alice_99");
    let trimmed_from_str = Username::from_string(padded.to_string()).unwrap();
    assert_eq!(trimmed_from_str.as_str(), "alice_99");
}

#[test]
fn empirical_verify_email_edge_cases() {
    assert_eq!(MAX_EMAIL_LENGTH, 254);

    // Empty and whitespace-only
    assert!(EmailAddress::parse("").is_err());
    assert!(EmailAddress::from_string(String::new()).is_err());
    assert!(EmailAddress::parse("   ").is_err());
    assert!(EmailAddress::from_string("   ".to_string()).is_err());

    // Length limit: valid RFC 5321 email with max 64-char local part
    // and labels within 63 chars each:
    // local (64) + '@' (1) + domain labels (63 + 1 + 60 + 1 + 59 + 1 + 4) = 254 chars total.
    let local_part = "a".repeat(64);
    let label1 = "b".repeat(63);
    let label2 = "c".repeat(60);
    let label3 = "d".repeat(59);
    let email_exact = format!("{local_part}@{label1}.{label2}.{label3}.info");
    assert_eq!(email_exact.len(), 254);
    assert!(
        EmailAddress::parse(&email_exact).is_ok(),
        "254-character compliant email should be accepted"
    );
    assert!(
        EmailAddress::from_string(email_exact.clone()).is_ok(),
        "from_string with 254-character compliant email should be accepted"
    );

    // Oversized (255 characters)
    let email_oversized = format!("a{email_exact}");
    assert_eq!(email_oversized.len(), 255);
    assert!(EmailAddress::parse(&email_oversized).is_err());
    assert!(EmailAddress::from_string(email_oversized).is_err());

    // Case normalization and whitespace trimming
    let mixed = "   Alice.Smith+Tag@EXAMPLE.COM  \n";
    let email_parsed = EmailAddress::parse(mixed).unwrap();
    assert_eq!(email_parsed.as_str(), "alice.smith+tag@example.com");

    let email_from_str = EmailAddress::from_string(mixed.to_string()).unwrap();
    assert_eq!(email_from_str.as_str(), "alice.smith+tag@example.com");

    // In-place lowercase conversion when string is already trimmed
    let already_trimmed_upper = "ALICE@EXAMPLE.COM".to_string();
    let email_inplace = EmailAddress::from_string(already_trimmed_upper).unwrap();
    assert_eq!(email_inplace.as_str(), "alice@example.com");

    // Strict invalid RFC syntax rejection
    for invalid in [
        "not-an-email",
        "@missing-local.com",
        "missing-domain@",
        "spaces in@local.com",
        "user@.invalid.com",
        "user@domain..com",
    ] {
        assert!(
            EmailAddress::parse(invalid).is_err(),
            "Expected '{invalid}' to be rejected"
        );
        assert!(
            EmailAddress::from_string(invalid.to_string()).is_err(),
            "Expected from_string('{invalid}') to be rejected"
        );
    }

    // Parity between parse and from_string across a test corpus
    let corpus = [
        "user@example.com",
        "USER@EXAMPLE.COM",
        "  User.Name+Tag@Sub.Example.Co.UK  ",
        "invalid..email@",
        "plainaddress",
        "",
        "   ",
    ];
    for input in corpus {
        let from_parse = EmailAddress::parse(input).map(|e| e.into_inner());
        let from_string = EmailAddress::from_string(input.to_string()).map(|e| e.into_inner());
        assert_eq!(
            from_parse, from_string,
            "Discrepancy between parse and from_string for input: '{input}'"
        );
    }
}

#[test]
fn empirical_verify_email_unicode_and_dummy_backup_code() {
    // Check validator's handling of non-ASCII characters
    let non_ascii_email = "TEST@EXÁMPLE.COM";
    let parsed = EmailAddress::parse(non_ascii_email);
    let from_string = EmailAddress::from_string(non_ascii_email.to_string());
    println!("parsed: {:?}", parsed);
    println!("from_string: {:?}", from_string);
    assert_eq!(parsed, from_string);

    // Verify DUMMY_BACKUP_HASH candidate attack
    let dummy_hash_str = "0000000000000000000000000000000000000000000000000000000000000000";
    let mut mfa = UserMfa::new(
        UserId::new(),
        vec![1, 2, 3],
        [0u8; 12],
        vec!["real_hash_1".to_string(), "real_hash_2".to_string()],
    );
    // Attacker submitting DUMMY_BACKUP_HASH must NOT match dummy entries
    assert!(!mfa.consume_backup_code(dummy_hash_str));
    assert_eq!(mfa.remaining_backup_codes_count(), 2);
}
