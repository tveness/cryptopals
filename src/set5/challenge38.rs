//! Offline dictionary attack on simplified SRP
//!
//! S
//! x = SHA256(salt|password)
//!     v = g**x % n
//! C->S
//! I, A = g**a % n
//! S->C
//! salt, B = g**b % n, u = 128 bit random number
//! C
//! x = SHA256(salt|password)
//!     S = B**(a + ux) % n
//!     K = SHA256(S)
//! S
//! S = (A * v ** u)**b % n
//!     K = SHA256(S)
//! C->SSend HMAC-SHA256(K, salt)
//! S->CSend "OK" if HMAC-SHA256(K, salt) validates
//! Note that in this protocol, the server's "B" parameter doesn't depend on the password (it's
//! just a Diffie Hellman public key).
//!
//! Make sure the protocol works given a valid password.
//!
//! Now, run the protocol as a MITM attacker: pose as the server and use arbitrary values for b, B,
//! u, and salt.
//!
//! Crack the password from A's HMAC-SHA256(K, salt).

use crate::{dh::nist_params, utils::*};
use num_bigint::{BigInt, RandBigInt, Sign};
use num_traits::Zero;
use openssl::sha::sha256;
use rand::{distributions::Alphanumeric, thread_rng, Rng};

pub fn main() -> Result<()> {
    println!("=== BEGIN REGULAR ===");

    let (p, g) = nist_params();

    let mut rng = thread_rng();
    let salt = rng.gen::<usize>();
    let password_bytes: Vec<u8> = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(22)
        .map(u8::from)
        .collect();
    let mut saltpass: Vec<u8> = vec![];
    saltpass.extend_from_slice(&salt.to_be_bytes());
    saltpass.extend_from_slice(&password_bytes);
    let xh = sha256(&saltpass);
    {
        // Server
        let x = BigInt::from_bytes_be(Sign::Plus, &xh);
        let v = g.modpow(&x, &p);

        // Client -> Server
        let a: BigInt = rng.gen_bigint_range(&Zero::zero(), &p);
        let pub_a = g.modpow(&a, &p);

        // Server -> Client
        let b: BigInt = rng.gen_bigint_range(&Zero::zero(), &p);
        let pub_b = g.modpow(&b, &p);
        let u = rng.gen_biguint(128).into();

        // Client, also calculates x
        let exp = &a + &u * &x;
        let s_client = pub_b.modpow(&exp, &p);
        println!("S(client): {s_client}");
        let k_client = sha256(&s_client.to_bytes_be().1);
        println!("K(client): {}", bytes_to_hex(&k_client));

        let vu = v.modpow(&u, &p);
        let s_server = (&pub_a * &vu).modpow(&b, &p);
        println!("S(client): {s_server}");
        let k_server = sha256(&s_server.to_bytes_be().1);
        println!("K(server): {}", bytes_to_hex(&k_server));

        let salt_bytes = salt.to_be_bytes();
        let hmac_client = hmac_sha256::HMAC::mac(salt_bytes, k_client);
        println!("Client hmac: {}", bytes_to_hex(&hmac_client));
        let hmac_server = hmac_sha256::HMAC::mac(salt_bytes, k_server);
        println!("server hmac: {}", bytes_to_hex(&hmac_server));

        assert_eq!(hmac_client, hmac_server);
    }

    println!("=== MITM ===");
    // We get to pick arbitrary values for b, B, u, and salt
    // What does the client calculate using these?
    // s_client = B**(a+ux)
    // s_server = (A* v**u)**(b) = A**b * v**ub
    // v = g**x => s_server = A**b * g**(bux), which is the same

    // This is called an offline dictionary attack. Why?
    // Well, if we weren't able to inject any parameters, we'd know the salt, A, B, u
    // What can we do with these? We can't event guess s, because this needs knowledge of the hash
    // x
    // s_server = A**b * g**(bux)
    // If we pick B=0, then s_client = 0, and hamc_client is boring
    // s_client = B**(a+ux),
    // seems easier to set b=1, u=1
    // Then
    // s_client = g**(a+x)
    //          = A * g**(x)
    // And we know A
    // Now we run through the dictionary and try all of the hashes with the fixed salt, which are
    // stored

    // Read all sowpods into an array
    let passwords: Vec<String> = std::fs::read_to_string("./data/sowpods.txt")
        .unwrap()
        .split('\n')
        .map(String::from)
        .take(1000)
        .collect::<Vec<String>>();
    let random_pw_index = rng.gen::<usize>() % passwords.len();
    println!("Chosen password is: {}", passwords[random_pw_index]);

    let mut rng = thread_rng();

    let a: BigInt = rng.gen_bigint_range(&Zero::zero(), &p);
    let pub_a: BigInt = g.modpow(&a, &p);
    let u: BigInt = 1.into();
    let b: BigInt = 1.into();

    let client_hmac = hmac_from_pw_client(&passwords[random_pw_index], &u, &a, &b, &g, &p);
    println!("Client hmac: {}", bytes_to_hex(&client_hmac));

    let cracked_pw = passwords
        .iter()
        .find(|pw| hmac_from_pw_server(pw, &pub_a, &g, &p) == client_hmac)
        .unwrap();
    println!("Cracked pw: {cracked_pw}");

    let server_hmac = hmac_from_pw_server(&passwords[random_pw_index], &pub_a, &g, &p);

    println!("Server hmac: {}", bytes_to_hex(&server_hmac));

    Ok(())
}
fn hmac_from_pw_server(password: &str, pub_a: &BigInt, g: &BigInt, p: &BigInt) -> Vec<u8> {
    let password_bytes = password.as_bytes();
    let mut saltpass: Vec<u8> = vec![1];
    saltpass.extend_from_slice(password_bytes);
    let xh = sha256(&saltpass);
    let x = BigInt::from_bytes_be(Sign::Plus, &xh);
    let s_server = (pub_a * g.modpow(&x, p)) % p;
    let k_server = sha256(&s_server.to_bytes_be().1);
    let hmac_server = hmac_sha256::HMAC::mac([1], k_server);
    hmac_server.to_vec()
}

fn hmac_from_pw_client(
    password: &str,
    u: &BigInt,
    a: &BigInt,
    b: &BigInt,
    g: &BigInt,
    p: &BigInt,
) -> Vec<u8> {
    let mut saltpass: Vec<u8> = vec![1];
    let password_bytes = password.as_bytes();
    saltpass.extend_from_slice(password_bytes);
    let xh = sha256(&saltpass);

    let x = BigInt::from_bytes_be(Sign::Plus, &xh);

    // Client, also calculates x
    let exp = a + u * &x;
    let pub_b = g.modpow(b, p);
    let s_client = pub_b.modpow(&exp, p);
    println!("S(client): {s_client}");
    let k_client = sha256(&s_client.to_bytes_be().1);
    println!("K(client): {}", bytes_to_hex(&k_client));

    let hmac_client = hmac_sha256::HMAC::mac([1], k_client);
    hmac_client.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn srp_dict() {
        main().unwrap();
    }
}
