//! Break SRP with a zero key
//!
//! Get your SRP working in an actual client-server setting. "Log in" with a valid password using
//! the protocol.
//!
//! Now log in without your password by having the client send 0 as its "A" value. What does this
//! to the "S" value that both sides compute?
//!
//! Now log in without your password by having the client send N, N*2, &c. Cryptanalytic MVP award
//!
//! Trevor Perrin and Nate Lawson taught us this attack 7 years ago. It is excellent. Attacks on DH
//! are tricky to "operationalize". But this attack uses the same concepts, and results in auth
//! bypass. Almost every implementation of SRP we've ever seen has this flaw; if you see a new one,
//! go look for this bug.

use crate::utils::*;
use num_bigint::{BigInt, RandBigInt};
use num_traits::Zero;
use openssl::sha::sha256;
use rand::{distributions::Alphanumeric, thread_rng, Rng};

use crate::dh::nist_params;

struct SrpServer {
    p: BigInt,
    g: BigInt,
    k: BigInt,
    v: BigInt,
    b: BigInt,
    salt: usize,
}

impl SrpServer {
    fn new(password_bytes: &[u8]) -> Self {
        let (p, g) = nist_params();
        let k: BigInt = 3.into();
        let mut rng = thread_rng();
        let salt = rng.gen::<usize>();
        let mut saltpass: Vec<u8> = vec![];
        saltpass.extend_from_slice(&salt.to_be_bytes());
        saltpass.extend_from_slice(password_bytes);

        let xh = sha256(&saltpass);
        let x = BigInt::from_bytes_be(num_bigint::Sign::Plus, &xh);

        let v = g.modpow(&x, &p);
        let b: BigInt = rng.gen_bigint_range(&Zero::zero(), &p);

        Self {
            p,
            g,
            k,
            v,
            b,
            salt,
        }
    }

    fn pub_b(&self) -> BigInt {
        let pub_b: BigInt = (&self.k * &self.v + self.g.modpow(&self.b, &self.p)) % &self.p;
        pub_b
    }

    fn u(&self, pub_a: &BigInt) -> BigInt {
        let pub_b = self.pub_b();
        let mut pub_apub_b: Vec<u8> = vec![];
        pub_apub_b.extend_from_slice(&pub_a.to_bytes_be().1);
        pub_apub_b.extend_from_slice(&pub_b.to_bytes_be().1);

        let uh = sha256(&pub_apub_b);
        BigInt::from_bytes_be(num_bigint::Sign::Plus, &uh)
    }

    fn server_hmac(&self, pub_a: &BigInt) -> Vec<u8> {
        let u = self.u(pub_a);
        let server_s = (pub_a * self.v.modpow(&u, &self.p)).modpow(&self.b, &self.p);
        println!("Server s: {server_s}");
        let server_k = sha256(&server_s.to_bytes_be().1);
        let server_hmac = hmac_sha256::HMAC::mac(server_k, self.salt.to_be_bytes());
        server_hmac.to_vec()
    }
}

struct SrpClient {
    p: BigInt,
    g: BigInt,
    k: BigInt,
    a: BigInt,
    x: BigInt,
    salt: usize,
}

impl SrpClient {
    fn new(password_bytes: &[u8], salt: usize) -> Self {
        let mut rng = thread_rng();
        let (p, g) = nist_params();
        let k: BigInt = 3.into();

        let a: BigInt = rng.gen_bigint_range(&Zero::zero(), &p);

        let mut saltpass: Vec<u8> = vec![];
        saltpass.extend_from_slice(&salt.to_be_bytes());
        saltpass.extend_from_slice(password_bytes);

        let xh = sha256(&saltpass);
        let x = BigInt::from_bytes_be(num_bigint::Sign::Plus, &xh);

        Self {
            p,
            g,
            k,
            a,
            x,
            salt,
        }
    }

    fn pub_a(&self) -> BigInt {
        self.g.modpow(&self.a, &self.p)
    }

    fn u(&self, pub_b: &BigInt) -> BigInt {
        let pub_a = self.pub_a();
        let mut pub_apub_b: Vec<u8> = vec![];
        pub_apub_b.extend_from_slice(&pub_a.to_bytes_be().1);
        pub_apub_b.extend_from_slice(&pub_b.to_bytes_be().1);

        let uh = sha256(&pub_apub_b);
        BigInt::from_bytes_be(num_bigint::Sign::Plus, &uh)
    }

    fn client_hmac(&self, pub_b: &BigInt) -> Vec<u8> {
        let u = self.u(pub_b);
        let exp = &self.a + &u * &self.x;
        let s = (pub_b - &self.k * self.g.modpow(&self.x, &self.p)).modpow(&exp, &self.p);
        println!("Client s: {s}");
        let client_k = sha256(&s.to_bytes_be().1);
        let client_hmac = hmac_sha256::HMAC::mac(client_k, self.salt.to_be_bytes());
        client_hmac.to_vec()
    }
}

pub fn main() -> Result<()> {
    println!("=== REGULAR FLOW === ");
    {
        let _i = b"username@website.com";
        let password_bytes: Vec<u8> = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(22)
            .map(u8::from)
            .collect();

        // Initialise server
        let server = SrpServer::new(&password_bytes);
        let salt = server.salt;
        // Initialise client
        let client = SrpClient::new(&password_bytes, salt);

        let server_hmac = server.server_hmac(&client.pub_a());
        let pub_b = server.pub_b();

        let client_hmac = client.client_hmac(&pub_b);
        println!("Client hmac: {}", bytes_to_hex(&client_hmac));
        println!("Server hmac: {}", bytes_to_hex(&server_hmac));

        assert_eq!(client_hmac, server_hmac);
    }

    println!("=== ZERO PASSWORD FLOW === ");
    {
        let _i = b"username@website.com";
        let password_bytes: Vec<u8> = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(22)
            .map(u8::from)
            .collect();

        // Initialise server
        let server = SrpServer::new(&password_bytes);
        let salt = server.salt;
        // Don't even need a client
        // Set the password wrong
        let zero: BigInt = Zero::zero();

        let server_hmac = server.server_hmac(&zero);
        //let pub_b = server.pub_b();
        // This injection means that server_s = 0
        // And so server k = sha256(0)
        let deduced_server_k = sha256(&[0]);
        // And so server_hmac is trivially calculable
        let deduced_server_hmac =
            hmac_sha256::HMAC::mac(deduced_server_k, salt.to_be_bytes()).to_vec();
        println!(
            "Deduced server hmac: {}",
            bytes_to_hex(&deduced_server_hmac)
        );
        println!("Server hmac:         {}", bytes_to_hex(&server_hmac));

        assert_eq!(deduced_server_hmac, server_hmac);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_pub_key() {
        main().unwrap();
    }
}
