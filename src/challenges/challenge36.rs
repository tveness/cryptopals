//! Implement Secure Remote Password (SRP)
//!
//! To understand SRP, look at how you generate an AES key from DH; now, just observe you can do
//! the "opposite" operation an generate a numeric parameter from a hash. Then:
//!
//! Replace A and B with C and S (client & server)
//!
//! C & S
//! Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)
//! S
//! Generate salt as random integer
//! Generate string xH=SHA256(salt|password)
//! Convert xH to integer x somehow (put 0x on hexdigest)
//! Generate v=g**x % N
//! Save everything but x, xH
//! C->S
//! Send I, A=g**a % N (a la Diffie Hellman)
//! S->C
//! Send salt, B=kv + g**b % N
//! S, C
//! Compute string uH = SHA256(A|B), u = integer of uH
//! C
//! Generate string xH=SHA256(salt|password)
//! Convert xH to integer x somehow (put 0x on hexdigest)
//! Generate S = (B - k * g**x)**(a + u * x) % N
//! Generate K = SHA256(S)
//! S
//! Generate S = (A * v**u) ** b % N
//! Generate K = SHA256(S)
//! C->S
//! Send HMAC-SHA256(K, salt)
//! S->C
//! Send "OK" if HMAC-SHA256(K, salt) validates
//! You're going to want to do this at a REPL of some sort; it may take a couple tries.
//!
//! It doesn't matter how you go from integer to string or string to integer (where things are
//! going in or out of SHA256) as long as you do it consistently. I tested by using the ASCII
//! decimal representation of integers as input to SHA256, and by converting the hexdigest to an
//! integer when processing its output.
//!
//! This is basically Diffie Hellman with a tweak of mixing the password into the public keys. The
//! server also takes an extra step to avoid storing an easily crackable password-equivalent.

use num_bigint::{BigInt, RandBigInt};
use num_traits::Zero;
use openssl::sha::sha256;
use rand::{distributions::Alphanumeric, thread_rng, Rng};

use crate::{dh::nist_params, utils::*};

// What does this do? We have our standard DH procedure to establish a shared secret key, while
// exchanging information publicly. We also already have a shared secret we wish to confirm: the
// password.

// What do we do? We first encode the password by taking the hash with a salt, and calculating
// v = g**x mod p, on the server
//
// The client calculates the regular public key for A
//
// The server sends the salt, and mixes v in with the B public key
//
// The client takes that, and using their password, subtracts it off and has the regular public key
// B, and can now get the normal shared secret g**(a+b) mod p
// But this goes one further than that, and raises the shared secret to a further power of (u*x)
// Why? x depends on the password, and formally the shared secret wouldn't otherwise
// B - k v = g**b mod p
// => g**(b*(a+ux)) mod p
// => S * g**(bux) mod p
// => S * v**(ub) mod p
// x clearly has to be in there to actually verify the password
// What does u do? According to RFC 2945
// https://www.rfc-editor.org/rfc/rfc2945
// and
// http://srp.stanford.edu/ndss.html#SECTION00032200000000000000
// it is a "random scrambling parameter"
//
// If u were fixed, then the server secret would be S * v**(ub)
// If an attacker somehow captured v (which is stored on the server), then they would simply
// have to send A = g**a * v**(-u), where v**(-u) may be calculated via extended Euclidean
// Alg/Bezout's identity
// Then the server secret would become g**(ab), which the client can calculate from everythign
// known!

pub fn main() -> Result<()> {
    let (p, g) = nist_params();
    let k: BigInt = 3.into();

    let _i = b"username@website.com";
    let password_bytes: Vec<u8> = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(22)
        .map(u8::from)
        .collect();
    //let password = std::str::from_utf8(&password_bytes).unwrap();

    // Server
    let mut rng = thread_rng();
    let s_salt = rng.gen::<usize>();
    let mut saltpass: Vec<u8> = vec![];
    saltpass.extend_from_slice(&s_salt.to_be_bytes());
    saltpass.extend_from_slice(&password_bytes);

    let xh = sha256(&saltpass);
    let x = BigInt::from_bytes_be(num_bigint::Sign::Plus, &xh);

    let v = g.modpow(&x, &p);

    let a: BigInt = rng.gen_bigint_range(&Zero::zero(), &p);
    let pub_a = g.modpow(&a, &p);
    println!("Pub a: {pub_a}");

    // Send email, pub_a to server

    // Server

    let b: BigInt = rng.gen_bigint_range(&Zero::zero(), &p);
    let pub_b: BigInt = (&k * &v + g.modpow(&b, &p)) % &p;
    let mut pub_apub_b: Vec<u8> = vec![];
    pub_apub_b.extend_from_slice(&pub_a.to_bytes_be().1);
    pub_apub_b.extend_from_slice(&pub_b.to_bytes_be().1);

    let uh = sha256(&pub_apub_b);
    let u = BigInt::from_bytes_be(num_bigint::Sign::Plus, &uh);

    // Client
    // Client has s_salt from server, so can also compute x in the same way
    /*
    let one: BigInt = One::one();
    let derived_b = (&pub_b - &k * g.modpow(&x, &p)).modpow(&one, &p);
    println!("Actual B: {}", g.modpow(&b, &p));
    println!("Derived B: {derived_b}");
    */
    let exp = &a + &u * &x;
    let s = (&pub_b - &k * g.modpow(&x, &p)).modpow(&exp, &p);
    println!("Client s: {s}");
    let client_k = sha256(&s.to_bytes_be().1);
    let client_hmac = hmac_sha256::HMAC::mac(client_k, s_salt.to_be_bytes());

    println!("Client hmac: {}", bytes_to_hex(&client_hmac));
    // Server
    let server_s = (pub_a * v.modpow(&u, &p)).modpow(&b, &p);
    println!("Server s: {server_s}");
    let server_k = sha256(&server_s.to_bytes_be().1);

    let server_hmac = hmac_sha256::HMAC::mac(server_k, s_salt.to_be_bytes());
    println!("Server hmac: {}", bytes_to_hex(&server_hmac));

    assert_eq!(server_hmac, client_hmac);

    Ok(())
}
