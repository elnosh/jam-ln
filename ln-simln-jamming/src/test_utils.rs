use rand::{distributions::Uniform, Rng};

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

#[allow(dead_code)]
pub fn get_random_bytes(size: usize) -> Vec<u8> {
    rand::thread_rng()
        .sample_iter(Uniform::new(u8::MIN, u8::MAX))
        .take(size)
        .collect()
}

#[allow(dead_code)]
pub fn get_random_keypair() -> (SecretKey, PublicKey) {
    loop {
        if let Ok(sk) = SecretKey::from_slice(&get_random_bytes(32)) {
            return (sk, PublicKey::from_secret_key(&Secp256k1::new(), &sk));
        }
    }
}
