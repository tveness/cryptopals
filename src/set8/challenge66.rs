//! 66. Exploiting Implementation Errors in Diffie-Hellman
//!
//! Most of the problems we've exploited have been application- or
//! protocol-layer errors of design. But cryptographic primitives can
//! suffer from implementation errors too!
//!
//! One seldom-seen (but never the less deadly!) class of implementation
//! error is the notorious carry bug. It goes like this:
//!
//! 1. Most public-key (and some symmetric) cryptographic primitives take
//!    advantage of bignum arithmetic.
//!
//! 2. Bignums are big. They can be thousands of bits long. They do not
//!    fit in machine registers.
//!
//! 3. To compute the correct results, implementations are forced to break
//!    up bignums into pieces (henceforth "limbs") that will fit in
//!    registers.
//!
//! 4. Just like long addition in grade school, intermediate results are
//!    computed one column (pair of limbs) at a time.
//!
//! 5. Just like long addition in grade school, intermediate results can
//!    overflow. The implementation must track and apply all these carry
//!    bits with utmost care.
//!
//! 6. Finally, the implementation has to stitch all the limbs back into a
//!    coherent result.
//!
//! There are opportunities for errors everywhere, but step 5 is
//! especially pernicious. Carry bugs can be difficult to detect, since
//! the incidence of random faults might be 2^-64 or worse. And because
//! these bugs are so implementation-dependent, standard test vectors,
//! even those meant to exercise pathological cases, typically are not
//! very good at finding these flaws.
//!
//! Ladies and gentlemen, cryptopals, please: a moment of silence for the
//! crypto implementers.
//!
//! *Sheds a single tear*
//!
//! Okay, that's enough sympathy. Now let's find a nontrivial homomorphism
//! from their sorrow to the profit domain.
//!
//! Let's target Diffie-Hellman, the bread-and-butter public-key primitive
//! of cryptographic protocols. We'll stick with EC notation. Here's the
//! high-level view of scalar multiplication:
//!
//!   function scalarmult(Q, k):
//!       R := Q
//!
//!       # assume n-bit k with k[1] = 1
//!       # iterate bits from high to low, skip first bit
//!       for b in bits(k)[2..n]:
//!           R := add(R, R)
//!           if b = 1:
//!               R := add(R, Q)
//!
//!       return R
//!
//! In ECDH, Q is an attacker-supplied public point, and k is our secret
//! scalar. For simplicity, let's suppose k is a fixed bit-length. (This
//! is often true in DH implementations anyway.) We number the bits of k
//! from 1 to n with k[1] the most-significant bit and k[n] the
//! least-significant bit.
//!
//! We need to hide some low-level bug in this high-level logic. We could
//! go through the exercise of implementing multiple-precision arithmetic
//! with some subtle-but-realistic carry bug embedded deep within the
//! logic, but that would be incredibly tedious, and it would only
//! obfuscate what is (at heart) a beautifully simple attack.
//!
//! Instead, let's cheat:
//!
//! 1. If you worked through the previous ECDH problems, you should be
//!    able to borrow code from your existing implementation. If not, gin
//!    one up with the standard EC addition laws from Wikipedia.
//!
//! 2. Replace add() with faultyadd(), which should look something like
//!    this:
//!
//!      function faultyadd(Q1, Q2):
//!          if fault(Q1, Q2):
//!              raise
//!          return add(Q1, Q2)
//!
//! 3. Fault() should just hash the points and compare them to some
//!    sentinel value. I did something like this:
//!
//!      function fault(Q1, Q2):
//!          return (Q1.x * Q2.x) % p = 0
//!
//!    With p the probability of a fault.
//!
//! It doesn't really matter what fault() is, but it must be
//! deterministic. Just make sure it's not too slow, since it's going to
//! get called 2n times per scalar multiplication. And make sure you can
//! adjust p easily, for your own sanity.
//!
//! Before we think about how to attack, I think it's helpful to think
//! about the DH implementation above.
//!
//! Write yourself a little tracer that steps through a scalar
//! multiplication and, at each call to add, prints the coefficients c and
//! d of Q in each call add(cQ, dQ). Feel free to add whatever debug
//! outputs make sense.
//!
//! For example, with n = 6, trace(58) gives me:
//!
//!   # k = 111010
//!   # i = 2, b = 1
//!   add(1Q, 1Q)
//!   add(2Q, 1Q)
//!   # i = 3, b = 1
//!   add(3Q, 3Q)
//!   add(6Q, 1Q)
//!   # i = 4, b = 0
//!   add(7Q, 7Q)
//!   # i = 5, b = 1
//!   add(14Q, 14Q)
//!   add(28Q, 1Q)
//!   # i = 6, b = 0
//!   add(29Q, 29Q)
//!
//! And here's trace(62):
//!
//!   # k = 111110
//!   # i = 2, b = 1
//!   add(1Q, 1Q)
//!   add(2Q, 1Q)
//!   # i = 3, b = 1
//!   add(3Q, 3Q)
//!   add(6Q, 1Q)
//!   # i = 4, b = 1
//!   add(7Q, 7Q)
//!   add(14Q, 1Q)
//!   # i = 5, b = 1
//!   add(15Q, 15Q)
//!   add(30Q, 1Q)
//!   # i = 6, b = 0
//!   add(31Q, 31Q)
//!
//! Play around with different inputs until you get an intuitive feel for
//! it.
//!
//! Here are some things to note:
//!
//! 1. The coefficients of Q in each call to k is a function of the secret
//!    scalar alone. This implies another model for the secret: a unique
//!    sequence of group operations. While the attacker chooses the input
//!    point, the victim alone chooses the sequence of operations on it.
//!
//! 2. For any given k, each pair of inputs to add() is unique. That is,
//!    we never repeat a (Q1, Q2) pair. This is because the accumulator
//!    doubles in each iteration.
//!
//! 3. In each iteration, the inputs to add() depend on the current bit
//!    and all preceding bits. The succeeding bits are not considered
//!    until later. The two examples above differ only in k[4]. Notice
//!    that they encode an identical sequence of operations before
//!    diverging forever when i = 4.
//!
//! Another way to put this is that the bits of k encode a binary decision
//! tree:
//!
//!                        add(1Q, 1Q)
//!
//!                   /---/           \---\
//!
//!             b = 0                       b = 1
//!
//!          add(2Q, 2Q)                  add(2Q, 1Q)
//!                                       add(3Q, 3Q)
//!
//!          /         \                  /         \
//!
//!       b = 0       b = 1            b = 0        b = 1
//!
//!    add(4Q, 4Q)  add(4Q, 1Q)     add(6Q, 6Q)   add(6Q, 1Q)
//!                 add(5Q, 5Q)                   add(7Q, 7Q)
//!
//!                          ...
//!
//! And so on.
//!
//! Now, let's attack. We know k[1] = 1 by definition. Let's consider
//! k[2]. By inspecting the tree above, we can see add(2Q, 2Q) is computed
//! if and only if k[2] = 0.
//!
//! So:
//!
//! 1. Generate a random scalar d. Keep it secret and keep it safe. This
//!    is the target of our attack.
//!
//! 2. Define an oracle that accepts a point Q, multiplies it by d, and
//!    returns true or false depending upon whether a fault is
//!    triggered. In a realistic setting, this could be an endpoint that
//!    computes the ECDH handshake and decrypts a message. You can build
//!    this out if you're feeling fancy, but the artificial oracle is okay
//!    too.
//!
//! 3. Working offline, generate random points and compute add(1Q, 1Q)
//!    (the unconditional first step of the multiplication) followed by
//!    add(2Q, 2Q). You're looking for a point that survives the first
//!    addition and triggers a fault on the second one.
//!
//! 4. When you find a point that triggers a fault, query the oracle. The
//!    response from the oracle will tell you the value of k[2]. If it
//!    succeeds, k[2] = 1. If it triggers the fault, k[2] = 0 (probably.)
//!
//! Probably? Well, sure. There is, of course, a chance for false
//! positives. Since we're treating faults as random, there is a small but
//! nonzero chance your input point will trigger a fault on some later
//! step.
//!
//! We can eliminate these by improving our simulation:
//!
//! 1. Instead of simulating only the b = 0 branch, simulate both
//!    branches. Find a candidate point that triggers a fault on one but
//!    not the other.
//!
//! 2. Suppose your point triggers a fault when k[2] = 1. Query the
//!    oracle. If there is no fault, k[2] = 0. Otherwise, we are unsure,
//!    so return to step 1. (The same logic applies if your point triggers
//!    when k[2] = 0.)
//!
//! From here, we can generalize the above algorithm to recover succeeding
//! bits:
//!
//! 1. Generate random points and simulate the bits of the key that you
//!    know. Ensure there is no error.
//!
//! 2. Simulate all possible computations for the next unknown bit of the
//!    key. If you trigger a fault, proceed. Otherwise, return to step 1.
//!
//! 3. Query the oracle. A negative result leaks a key bit with
//!    certainty. A positive result (i.e. a fault) may leak a key
//!    bit. Depending on how you tuned your fault probability, this may
//!    give you enough confidence to proceed.
//!
//! 4. Rinse and repeat until all key bits are recovered.
//!
//! That's pretty much it.
//!
//! Well, there are a few opportunities to get fancy, if you feel so
//! inclined:
//!
//! 1. Even in the presence of uncertainty, positive results have
//!    value. You can calculate the probability of a false positive and
//!    determine whether you have enough confidence to proceed.
//!
//! 2. Once you have enough bits of the key, you can compute the remainder
//!    of the attack offline using standard discrete logarithm attacks
//!    (e.g. Pollard's kangaroo).

use crate::utils::*;

pub fn main() -> Result<()> {
    unimplemented!()
}
