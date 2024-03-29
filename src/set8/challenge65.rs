//! 65. Truncated-MAC GCM Revisited: Improving the Key-Recovery Attack
//!     via Ciphertext Length Extension
//!
//! In the last problem we saw that GCM is very difficult to use safely
//! with truncated authentication tags. An attacker can greatly improve
//! their chances of message forgery. After several successful forgeries,
//! they can recover the authentication key and forge messages at will.
//!
//! Niels Ferguson outlined these weaknesses (among others) in a short
//! memo written around the time of GCM's design. His final
//! recommendation? "[U]se it only with a 128-bit tag."
//!
//! NIST, in turn, absorbed his feedback and then published its official
//! GCM specification, which says to go ahead and use tags as short as 32
//! bits, if you feel like it. YOLO.
//!
//! Don't worry, NIST has full confidence in you: "knowledgeable security
//! professionals should be able to manage the risks in connection with
//! this attack, and its potential improvement".
//!
//! So what kind of advice does NIST offer to help you avert disaster? Two
//! pages of considerations culminating in tables specifying:
//!
//! 1. The maximum combined length of ciphertext and authenticated data in
//!    a single packet, and
//!
//! 2. The maximum number of invocations of the authenticated decryption
//!    function.
//!
//! While the latter restriction is pretty straightforwardly the
//! responsibility of the receiving party, the NIST document makes no
//! specific recommendations towards limiting packet length.
//!
//! Maybe it doesn't matter. As long as honest parties only generate
//! packets within the allowed parameters, we should be okay, right?
//!
//! Wrong. It is, in fact, possible to extend the length of valid
//! ciphertexts up to any length the receiver is willing to accept.
//!
//! Let's see how. First, recall the big picture. For a three-block
//! ciphertext, the MAC is calculated like this:
//!
//!     t = s + c1*h + c2*h^2 + c3*h^3 + c4*h^4
//!
//! The c1 block encodes the length, and [c2, c4] are the actual blocks of
//! ciphertext (in reverse order). s is an unknown mask generated using
//! the nonce and the encryption key.
//!
//! In the last exercise, we flipped bits in blocks of ciphertext to knock
//! down the effective security of the authentication function. We
//! restricted ourselves only to tamper with particular blocks: those in
//! which changes can be modeled as a linear function on the bits of the
//! authentication key. This includes every block that is a coefficient of
//! a term of the form h^(2^k).
//!
//! Well, not every block. We only used c2 and c4; we left c1 alone, even
//! though it is a coefficient of h = h^1 = h^(2^0). Keep that in mind,
//! we'll come back to it.
//!
//! Remember that with n full blocks we had 128*n free variables, which we
//! could use to force n-1 rows of our difference matrix Ad to zero. We'd
//! tweak one block arbitrarily and adjust the others to compensate. If we
//! tried to force n rows to zero, the only solution would be the all-zero
//! solution where we tweak nothing.
//!
//! Suppose we had an incomplete block. In our example above, suppose the
//! last block, c2, was only eight bytes. This is no big deal. We could
//! still use our 192 (count 'em) free variables to force at least one row
//! to zero. From there the attack would proceed the same way: get some
//! equations on h, increase your forgery chances, and eventually recover
//! the key. You know how it goes.
//!
//! Ferguson offers another possibility towards the end of his
//! memo. Instead of leaving the length block c1 alone, we tweak it to
//! complete the final block. In this case, we'd turn our 40-byte
//! ciphertext into a 48-byte ciphertext. This would give us an extra 64
//! bits to play with, bumping us up to 256. Note that this doesn't affect
//! any coefficients of non-h^(2^k) terms, so the difference is still a
//! linear function on the bits of h.
//!
//! More importantly, by introducing a tweak to the length block, we take
//! away the all-zero solution. This allows us to force a full n rows of
//! the difference matrix Ad to zero.
//!
//! Whereas before we were solving this equation:
//!
//!     T * d = 0
//!
//! Now we're solving this one:
//!
//!     T * d = t
//!
//! Where t is the nonzero difference in the first n rows of Ad induced by
//! our tweak to the length block. We want to solve for a vector d of
//! tweaks to our free variables to cancel out this difference. To find
//! the complete set of solutions for d, first find one particular
//! solution, then add onto it any vector from N(T).
//!
//! Implement this improvement. Alter your attack code to recognize and
//! take advantage of situations where the last block of ciphertext is
//! incomplete by tweaking the length block.
//!
//! Some caveats:
//!
//! 1. The dimensions of T and d will change. You should be able to work
//!    out how with a bit of deliberation.
//!
//! 2. As a consequence, N(T) may shrink drastically. And as a consequence
//!    of *that*, you may find that there is no tweak that results in a
//!    successful forgery. If this happens, you can fall back to your old
//!    code. Or just wait for a new message of a different length.

use crate::utils::*;

pub fn main() -> Result<()> {
    unimplemented!()
}
