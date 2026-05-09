use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};

fn main() {
    let mut rng = rand::rngs::OsRng {};
    let sk = SigningKey::generate(&mut rng);
    let vk = sk.verifying_key();

    std::fs::create_dir_all("fixtures/license").unwrap();
    std::fs::write("fixtures/license/test-private.key", sk.to_bytes()).unwrap();
    std::fs::write("fixtures/license/test-public.key", vk.to_bytes()).unwrap();

    let payload = r#"{"plan":"pro","org":"dbward-dev","issued_at":"2026-01-01T00:00:00Z","expires_at":"2099-12-31T23:59:59Z"}"#;
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());
    let sig = sk.sign(payload_b64.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    let license_key = format!("{payload_b64}.{sig_b64}");

    std::fs::write("fixtures/license/pro.license", &license_key).unwrap();
    println!("Generated fixtures/license/");
    println!("  test-private.key (32 bytes)");
    println!("  test-public.key  (32 bytes)");
    println!("  pro.license      ({} chars)", license_key.len());
}
