//! 63. Key-Recovery Attacks on GCM with Repeated Nonces
//!
//! GCM is the most widely deployed block cipher mode for authenticated
//! encryption with associated data (AEAD). It's basically just CTR mode
//! with a weird MAC function wrapped around it. The MAC function works by
//! evaluating a polynomial over GF(2^128).
//!
//! Remember how much trouble a repeated nonce causes for CTR mode
//! encryption? The same thing is true here: an attacker can XOR
//! ciphertexts together and recover plaintext using statistical methods.
//!
//! But there's an even more devastating consequence for GCM: it leaks the
//! authentication key immediately!
//!
//! Here's the high-level view:
//!
//! 1. The GCM MAC function (GMAC) works by building up a polynomial whose
//!    coefficients are the blocks of associated data (AD), the blocks of
//!    ciphertext (C), a block encoding the length of AD and C, and a
//!    block used to "mask" the output. Sort of like this:
//!
//!        AD*y^3 + C*y^2 + L*y + S
//!
//!    To calculate the MAC, we plug in the authentication key for y and
//!    evaluate.
//!
//! 2. AD, C, and their respective lengths are known. For a given message,
//!    the attacker knows everything about the MAC polynomial except the
//!    masking block
//!
//! 3. The masking block is generated using only the key and the nonce. If
//!    the nonce is repeated, the mask is the same. If we can collect two
//!    messages encrypted under the same nonce, they'll have used the same
//!    mask.
//!
//! 4. In this field, addition is XOR. We can XOR our two messages
//!    together to "wash out" the mask and recover a known polynomial with
//!    the authentication key as a root. We can factor the polynomial to
//!    recover the authentication key immediately.
//!
//! The last step probably feels a little magical, but you don't actually
//! need to understand it to implement the attack: you can literally just
//! plug the right values into a computer algebra system like SageMath and
//! hit "factor".
//!
//! But that's not satisfying. You didn't come this far to beat the game
//! on Easy Mode, did you?
//!
//! I didn't think so. Now, let's dig into that MAC function. Like I said,
//! a polynomial over GF(2^128).
//!
//! So far, all the fields we've worked with have been of prime size p,
//! i.e. GF(p). It turns out we can construct GF(q) for any q = p^k for
//! any positive integer k. GF(p) = GF(p^1) is just one form that's common
//! in cryptography. Another is GF(2^k), and in this case we have
//! GF(2^128).
//!
//! For GF(2^k), we'll represent its elements as polynomials with
//! coefficients in GF(2). That just means each coefficient will be 0 or
//! 1. Before we start talking about a particular field (i.e. a particular
//! choice of k), let's just talk about these polynomials. Here are some
//! of them:
//!
//!                     0
//!                     1
//!                 x
//!                 x + 1
//!           x^2
//!           x^2     + 1
//!           x^2 + x
//!           x^2 + x + 1
//!     x^3
//!     x^3           + 1
//!     x^3       + x
//!     x^3       + x + 1
//!     x^3 + x^2
//!     x^3 + x^2     + 1
//!     x^3 + x^2 + x
//!     x^3 + x^2 + x + 1
//!     ...
//!
//! And so forth.
//!
//! If you squint a little they look like the binary expansions of the
//! integers counting up from zero. This is convenient because it gives us
//! an obvious choice of representation in unsigned integers.
//!
//! Now we need some primitive functions for operating on these
//! polynomials. Let's tool up:
//!
//! 1. Addition and subtraction between GF(2) polynomials are really
//!    simple: they're both just the XOR function.
//!
//! 2. Multiplication and division are a little trickier, but they both
//!    just approximate the algorithms you learned in grade school. Here
//!    they are:
//!
//!        function mul(a, b):
//!             p := 0
//!
//!             while a > 0:
//!                 if a & 1:
//!                     p := p ^ b
//!
//!                 a := a >> 1
//!                 b := b << 1
//!
//!             return p
//!
//!         function divmod(a, b):
//!             q, r := 0, a
//!
//!             while deg(r) >= deg(b):
//!                 d := deg(r) - deg(b)
//!                 q := q ^ (1 << d)
//!                 r := r ^ (b << d)
//!
//!             return q, r
//!
//!    deg(a) is a function returning the degree of a polynomial. For the
//!    polynomial x^4 + x + 1, it should return 4. For 1, it should return
//!    0. For 0, it should return some negative value.
//!
//! Now that we have a small nucleus of functions to work on polynomials
//! in GF(2), let's see how we can use them to represent elements in
//! GF(2^k). To be concrete, let's say k = 4.
//!
//! Our set of elements is the same one enumerated above:
//!
//!                     0
//!                     1
//!                 x
//!                 x + 1
//!           x^2
//!           x^2     + 1
//!           x^2 + x
//!           x^2 + x + 1
//!     x^3
//!     x^3           + 1
//!     x^3       + x
//!     x^3       + x + 1
//!     x^3 + x^2
//!     x^3 + x^2     + 1
//!     x^3 + x^2 + x
//!     x^3 + x^2 + x + 1
//!
//! Addition and subtraction are unchanged. We still just XOR elements
//! together.
//!
//! Multiplication is different. As with fields of size p, we need to
//! perform modular reductions after each multiplication to keep our
//! elements in range. Our modulus will be x^4 + x + 1. If that seems a
//! little arbitrary, it is - we could use any fourth-degree monic
//! polynomial that's irreducible over GF(2). An irreducible polynomial is
//! sort of analogous to a prime number in this setting.
//!
//! Here's a naive modmul:
//!
//!     function modmul(a, b, m):
//!         p := mul(a, b)
//!         q, r := divmod(p, m)
//!         return r
//!
//! In practice, we'll want to be more efficient. So we'll interleave the
//! steps of the multiplication with steps of the reduction:
//!
//!     function modmul(a, b, m):
//!         p := 0
//!
//!         while a > 0:
//!             if a & 1:
//!                 p := p ^ b
//!
//!             a := a >> 1
//!             b := b << 1
//!
//!             if deg(b) = deg(m):
//!                 b := b ^ m
//!
//!         return p
//!
//! You can implement both versions to prove to yourself that the output
//! is the same.
//!
//! Division is also different. Remember that in fields of size p we
//! defined it as multiplication by the inverse. So you'll need to write a
//! modinv function. It should be pretty easy to translate your existing
//! integer modinv function. I'll leave that to you.
//!
//! You may find yourself in want of other functions you take for granted
//! in the integer setting, e.g. modexp. Most of these should have
//! straightforward equivalents in our polynomial setting. Do what you
//! need to.
//!
//! Okay, now that you are the master of GF(2^k), we can finally talk
//! about GCM. Like I said (many words ago): CTR mode for encryption,
//! weird MAC in GF(2^128).
//!
//! Here's the modulus for that field:
//!
//!     x^128 + x^7 + x^2 + x + 1
//!
//! The size of this field was chosen very specifically to match up with
//! the width of a 128-bit block cipher. We can convert a block into a
//! field element trivially; the leftmost bit is the coefficient of x^0,
//! and so on.
//!
//! I described the MAC at a very high level. Here's a more detailed view:
//!
//! 1. Take your AES key and use it to encrypt a block of zeros:
//!
//!        h := E(K, 0)
//!
//!    h is your authentication key. Convert it into a field element.
//!
//! 1. Zero-pad the bytes of associated data (AD) to be divisible by the
//!    block length. If it's already aligned on a block, leave it
//!    alone. Do the same with the ciphertext. Chain them together so you
//!    have something like:
//!
//!        a0 || a1 || c0 || c1 || c2
//!
//! 2. Add one last block describing the length of the AD and the length
//!    of the ciphertext. Original lengths, not padded lengths; bit
//!    lengths, not byte lengths. Like this:
//!
//!        len(AD) || len(C)
//!
//! 3. Take h and your string of blocks and do this:
//!
//!        g := 0
//!        for b in bs:
//!            g := g + b
//!            g := g * h
//!
//!    Convert the blocks into field elements first, of course. The
//!    resulting value of g is a keyed hash of the input blocks.
//!
//! 4. GCM takes a 96-bit nonce. Do this with it:
//!
//!        s := E(K, nonce || 1)
//!        t := g + s
//!
//!    Conceptually, we're masking the hash with a nonce-derived secret
//!    value. More on that later.
//!
//!    t is your tag. Convert it back to a block and ship it.
//!
//! Implement GCM. Use AES-128 as your block cipher. You can probably
//! reuse whatever you had before for CTR mode. The important new thing to
//! implement here is the MAC. The above description is brief and
//! informal; check out the spec for the finer points. Since you've
//! already got the tools for working in GF(2^k), this shouldn't take too
//! long.
//!
//! Okay. Let's rethink our view of the MAC. We'll use our example payload
//! from above. Here it is:
//!
//!     t = (((((((((((h * a0) + a1) * h) + c0) * h) + c1) * h) + c2) * h) + len) * h) + s
//!
//! Kind of a mouthful. Let's rewrite it:
//!
//!     t = a0*h^6 + a1*h^5 + c0*h^4 + c1*h^3 + c2*h^2 + len*h + s
//!
//! In other words, we calculate the MAC by constructing this polynomial:
//!
//!     f(y) = a0*y^6 + a1*y^5 + c0*y^4 + c1*y^3 + c2*y^2 + len*y + s
//!
//! And computing t = f(h).
//!
//! Remember: as the attacker, we don't know that whole polynomial. We
//! know all the AD and ciphertext coefficients, and we know t = f(h), but
//! we don't know the mask s.
//!
//! What happens if we repeat a nonce? Let's posit this additional payload
//! encrypted under the same nonce:
//!
//!     b0 || d0 || d1
//!
//! That's one block of AD and two blocks of ciphertext. The MAC will look
//! like this:
//!
//!     t = b0*h^4 + d0*h^3 + d1*h^2 + len*h + s
//!
//! Let's put them side by side (and rewrite them a little):
//!
//!     t0 = a0*h^6 + a1*h^5 + c0*h^4 + c1*h^3 + c2*h^2 + l0*h + s
//!     t1 =                   b0*h^4 + d0*h^3 + d1*h^2 + l1*h + s
//!
//! See how the s masks are identical? They depend only on the nonce and
//! the encryption key. Since addition is XOR in our field, we can add
//! these two equations together and that mask will wash right out:
//!
//!     t0 + t1 = a0*h^6 + a1*h^5 + (c0 + b0)*h^4 + (c1 + d0)*h^3 +
//!               (c2 + d1)*h^2 + (l0 + l1)*h
//!
//! Finally, we'll collect all the terms on one side:
//!
//!     0 = a0*h^6 + a1*h^5 + (c0 + b0)*h^4 + (c1 + d0)*h^3 +
//!         (c2 + d1)*h^2 + (l0 + l1)*h + (t0 + t1)
//!
//! And rewrite it as a polynomial in y:
//!
//!     f(y) = a0*y^6 + a1*y^5 + (c0 + b0)*y^4 + (c1 + d0)*y^3 +
//!            (c2 + d1)*y^2 + (l0 + l1)*y + (t0 + t1)
//!
//! Now we know a polynomial f(y), and we know that f(h) = 0. In other
//! words, the authentication key is a root. That means all we have to do
//! is factor the equation to get an extremely short list of candidates
//! for the authentication key. This turns out not to be so hard, but we
//! will need some more tools.
//!
//! First, we need to be able to operate on polynomials with coefficients
//! in GF(2^128).
//!
//! (Don't get confused: before we used polynomials with coefficients in
//! GF(2) to represent elements in GF(2^128). Now we're building on top of
//! that to work with polynomials with coefficients in GF(2^128).)
//!
//! The simplest representation is probably just an array of field
//! elements. The algorithms are all going to be basically the same as
//! above, so I'm not going to reiterate them here. The only difference is
//! that you will need to call your primitive functions for GF(2^k)
//! polynomials in place of your language's built-in arithmetic operators.
//!
//! With that out of the way, let's get factoring. Factoring a polynomial
//! over a finite field means separating it out into smaller polynomials
//! that are irreducible over the field. Remember that irreducible
//! polynomials are sort of like prime numbers.
//!
//! To factor a polynomial, we proceed in three (well, four) phases:
//!
//! 0. As a preliminary step, we need to convert our polynomial to a monic
//!    polynomial. That just means the leading coefficient is 1. So take
//!    your polynomial and divide it by the coefficient of the leading
//!    term. You can save the coefficient as a degree zero factor if you
//!    want, but it's not really important for our purposes.
//!
//! 1. This is the real first step: we perform a square-free
//!    factorization. We find any doubled factors (i.e. "squares") and
//!    split them out.
//!
//! 2. Next, We take each of our square-free polynomials and find its
//!    distinct-degree factorization. This separates out polynomials that
//!    are products of smaller polynomials of equal degree. So if our
//!    polynomial has three irreducible factors of degree four, this will
//!    separate out a polynomial of degree twelve that is the product of
//!    all of them.
//!
//! 3. Finally, we take each output from the last step and perform an
//!    equal-degree factorization. This is pretty much like it sounds. In
//!    that last example, we'd take that twelfth-degree polynomial and
//!    factor it into its fourth-degree components.
//!
//! Square-free factorization and distinct-degree factorization are both
//! easy to implement. Just find them on Wikipedia and go to town.
//!
//! I want to focus on equal-degree factorization. Meet Cantor-Zassenhaus:
//!
//!     function edf(f, d):
//!         n := deg(f)
//!         r := n / d
//!         S := {f}
//!
//!         while len(S) < r:
//!             h := random_polynomial(1, f)
//!             g := gcd(h, f)
//!
//!             if g = 1:
//!                 g := h^((q^d - 1)/3) - 1 mod f
//!
//!             for u in S:
//!                 if deg(u) = d:
//!                     continue
//!
//!                 if gcd(g, u) =/= 1 and gcd(g, u) =/= u:
//!                     S := union(S - {u}, {gcd(g, u), u / gcd(g, u)})
//!
//!         return S
//!
//! It's kind of brilliant.
//!
//! Remember earlier that we said a finite field of size p^k can be
//! represented as a polynomial in GF(p) modulo any monic, irreducible
//! degree-k polynomial? Take a moment to convince yourself that a field
//! of size q^d can be represented by polynomials in GF(q) modulo a
//! polynomial of degree d.
//!
//! f is the product of r polynomials of degree d. Each of them is a valid
//! modulus for a finite field of size q^d. And each field of that size
//! contains a multiplicative group of size q^d - 1. And since q^d - 1 is
//! always divisible by 3 (in our case), each group of that size has a
//! subgroup of size 3. It contains the multiplicative identity (1) and
//! two other elements.
//!
//! We have a simple trick for forcing elements into that subgroup: simply
//! raise them to the exponent (q^d - 1)/3. When we force our random
//! element into that subgroup, there's a 1/3 chance we'll land on 1. This
//! means that when we subtract 1, there's a 1/3 chance we'll be sitting
//! on 0.
//!
//! The only hitch is that we don't know what these moduli are. But we
//! don't need to! Since f is their product, we can perform these
//! operations mod f and implicitly apply the Chinese Remainder Theorem.
//!
//! So we do it: generate some polynomial, raise it to (q^d - 1)/3, and
//! subtract 1. (All modulo f, of course.) Compute the GCD of this
//! polynomial and each of our remaining composites. For any given
//! remaining factor, there's a 1/3 chance our polynomial is a
//! multiple. In other words, our factors should reveal themselves pretty
//! quickly.
//!
//! Just keep doing this until the whole thing is factored into
//! irreducible parts.
//!
//! Once the polynomial is factored, we can pick out the authentication
//! key at our leisure. There will be at least one first-degree
//! factor. Like this:
//!
//!     y + c
//!
//! Where c is a constant element of GF(2^128). It's also a candidate for
//! the key. It's possible you'll end up with a few first-degree factors
//! like this. The key will be one of them.
//!
//! If you do have more than one candidate, there are two ways to narrow
//! the list:
//!
//! 1. Recover another pair of messages encrypted under the same
//!    nonce. Perform the factorization again and identify the common
//!    factors. The key will probably be the only one.
//!
//! 2. Just attempt a forgery with each candidate. This is probably
//!    easier.

use crate::utils::*;

pub fn main() -> Result<()> {
    unimplemented!()
}
