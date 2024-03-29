//! 62. Key-Recovery Attacks on ECDSA with Biased Nonces
//!
//! Back in set 6 we saw how "nonce" is kind of a misnomer for the k value
//! in DSA. It's really more like an ephemeral key. And distressingly, the
//! security of your long-term private key hinges on it.
//!
//! Nonce disclosure? Congrats, you just coughed up your secret key.
//!
//! Predictable nonce? Ditto.
//!
//! Even by repeating a nonce you lose everything.
//!
//! How far can we take this? Turns out, pretty far: even a slight bias in
//! nonce generation is enough for an attacker to recover your private
//! key. Let's see how.
//!
//! First, let's clarify what we mean by a "biased" nonce. All we really
//! need for this attack is knowledge of a few bits of the nonce. For
//! simplicity, let's say the low byte of each nonce is zero. So take
//! whatever code you were using for nonce generation and just mask off
//! the eight least significant bits.
//!
//! How does this help us? Let's review the signing algorithm:
//!
//!     function sign(m, d):
//!         k := random_scalar(1, q)
//!         r := (k * G).x
//!         s := (H(m) + d*r) * k^-1
//!         return (r, s)
//!
//! (Quick note: before we used "n" to mean the order of the base
//! point. In this problem I'm going to use "q" to avoid naming
//! collisions. Deal with it.)
//!
//! Focus on the s calculation. Observe that if the low l bits of k are
//! biased to some constant c, we can rewrite k as b*2^l + c. In our case,
//! c = 0, so we'll instead rewrite k as b*2^l. This means we can relate
//! the public r and s values like this:
//!
//!     s = (H(m) + d*r) * (b*2^l)^-1
//!
//! Some straightforward algebra gets us from there to here:
//!
//!     d*r / (s*2^l) = (H(m) / (-s*2^l)) + b
//!
//! Remember that these calculations are all modulo q, the order of the
//! base point. Now, let's define some stand-ins:
//!
//!     t =    r / ( s*2^l)
//!     u = H(m) / (-s*2^l)
//!
//! Now our equation above can be written like this:
//!
//!     d*t = u + b
//!
//! Remember that b is small. Whereas t, u, and the secret key d are all
//! roughly the size of q, b is roughly q/2^l. It's a rounding
//! error. Since b is so small, we can basically just ignore it and say:
//!
//!     d*t ~ u
//!
//! In other words, u is an approximation for d*t mod q. Let's massage the
//! numbers some more. Since this is mod q, we can instead say this:
//!
//!     d*t ~ u + m*q
//!       0 ~ u + m*q - d*t
//!
//! That sum won't really be zero - it's just an approximation. But it
//! will be less than some bound, say q/2^l. The point is that it will be
//! very small relative to the other terms in play.
//!
//! We can use this property to recover d if we have enough (u, t)
//! pairs. But to do that, we need to know a little bit of linear
//! algebra. Not too much, I promise.
//!
//! Linear algebra is about vectors. A vector could be almost anything,
//! but for simplicity we'll say a vector is a fixed-length sequence of
//! numbers. There are two main things we can do with vectors: we can add
//! them and we can multiply them by scalars. To add two vectors, simply
//! sum their pairwise components. To multiply a vector by a scalar k,
//! simply add it to itself k times. (Equivalently, multiply each of its
//! elements by the scalar.) Together, these operations are called linear
//! combinations.
//!
//! If we have a set of vectors, we say they span a vector space. The
//! vector space is simply the full range of possible vectors we can
//! generate by adding and scaling the vectors in our set. We call a
//! minimal spanning set a basis for the vector space. "Minimal" means
//! that dropping any of our vectors from the set would result in a
//! smaller vector space. Added vectors would either be redundant
//! (i.e. they could be defined as sums of existing vectors) or they would
//! give us a larger vector space. So you can think of a basis as "just
//! right" for the vector space it spans.
//!
//! We're only going to use integers as our scalars. A vector space
//! generated using only integral scalars is called a lattice. It's best
//! to picture this in the two-dimensional plane. Suppose our set of
//! vectors is {(3, 4), (2, 1)}. The lattice includes all integer
//! combinations of these two pairs. You can graph this out on paper to
//! get the idea; you should end up with a polka dot pattern of sorts.
//!
//! We said that a basis is just the right size for the vector space it
//! spans, but that shouldn't be taken to imply uniqueness. Indeed, any of
//! the lattices we will care about have infinite possible bases. The only
//! requirements are that the basis spans the space and the basis is
//! minimal in size. In that sense, all bases of a given lattice are
//! equal.
//!
//! But some bases are more equal than others. In practice, people like to
//! use bases comprising shorter vectors. Here "shorter" means, roughly,
//! "containing smaller components on average". A handy measuring stick
//! here is the Euclidean norm: simply take the dot product of a vector
//! with itself and take the square root. Or don't take the square root, I
//! don't care. It won't affect the ordering.
//!
//! Why do people like these smaller bases? Mostly because they're more
//! efficient for computation. Honestly, it doesn't matter too much why
//! people like them. The important thing is that we have relatively
//! efficient methods for "reducing" a basis. Given an input basis, we can
//! produce an equivalent-but-with-much-shorter-vectors basis. How much
//! shorter? Well, maybe not the very shortest possible, but pretty darn
//! short.
//!
//! This implies a really neat approach to problem-solving:
//!
//! 1. Encode your problem space as a set of vectors forming the basis for
//!    a lattice. The lattice you choose should contain the solution
//!    you're looking for as a short vector. You don't need to know the
//!    vector (obviously, since you're looking for it), you just need to
//!    know that it exists as some integral combination of your basis
//!    vectors.
//!
//! 2. Derive a reduced basis for the lattice. We'll come back to this.
//!
//! 3. Fish your solution vector out of the reduced basis.
//!
//! 4. That's it.
//!
//! Wait, that's it? Yeah, you heard me - lattice basis reduction is an
//! incredibly powerful technique. It single-handedly shattered knapsack
//! cryptosystems back in the '80s, and it's racked up a ton of trophies
//! since then. As long as you can define a lattice containing a short
//! vector that encodes the solution to your problem, you can put it to
//! work for you.
//!
//! Obviously, defining the lattice is the tricky bit. How do we encode
//! ECDSA? Well, when we left off, we had the following approximation:
//!
//!     0 ~ u + m*q - d*t
//!
//! Suppose we collect a bunch of signatures. Then that one approximation
//! becomes many:
//!
//!     0 ~ u1 + m1*q - d*t1
//!     0 ~ u2 + m2*q - d*t2
//!     0 ~ u3 + m3*q - d*t3
//!     0 ~ u4 + m4*q - d*t4
//!     0 ~ u5 + m5*q - d*t5
//!     0 ~ u6 + m6*q - d*t6
//!     ...
//!     0 ~ un + mn*q - d*tn
//!
//! The coefficient for each u is always 1, and the coefficient for t is
//! always the secret key d. So it seems natural that we should line those
//! up in two vectors:
//!
//!     bt = [ t1 t2 t3 t4 t5 t6 ... tn ]
//!
//!     bu = [ u1 u2 u3 u4 u5 u6 ... un ]
//!
//! Each approximation also contains some factor of q. But the coefficient
//! m is different each time. That means we'll need a separate vector for
//! each one:
//!
//!     b1 = [  q  0  0  0  0  0 ...  0 ]
//!
//!     b2 = [  0  q  0  0  0  0 ...  0 ]
//!
//!     b3 = [  0  0  q  0  0  0 ...  0 ]
//!
//!     b4 = [  0  0  0  q  0  0 ...  0 ]
//!
//!     b5 = [  0  0  0  0  q  0 ...  0 ]
//!
//!     b6 = [  0  0  0  0  0  q ...  0 ]
//!
//!             ...              ...
//!
//!     bn = [  0  0  0  0  0  0 ...  q ]
//!
//!     bt = [ t0 t1 t2 t3 t4 t5 ... tn ]
//!
//!     bu = [ u0 u1 u2 u3 u4 u5 ... un ]
//!
//! See how the columns cutting across our row vectors match up with the
//! approximations we collected above? Notice also that the lattice
//! defined by this basis contains at least one reasonably short vector
//! we're interested in:
//!
//!     bu - d*bt + m0*b1 + m1*b2 + m2*b3 ... + mn*bn
//!
//! But we have a problem: even if this vector is included in our reduced
//! basis, we have no way to identify it. We can solve this by adding a
//! couple new columns.
//!
//!     b1 = [  q  0  0  0  0  0 ...  0  0  0 ]
//!
//!     b2 = [  0  q  0  0  0  0 ...  0  0  0 ]
//!
//!     b3 = [  0  0  q  0  0  0 ...  0  0  0 ]
//!
//!     b4 = [  0  0  0  q  0  0 ...  0  0  0 ]
//!
//!     b5 = [  0  0  0  0  q  0 ...  0  0  0 ]
//!
//!     b6 = [  0  0  0  0  0  q ...  0  0  0 ]
//!
//!             ...              ...
//!
//!     bn = [  0  0  0  0  0  0 ...  q  0  0 ]
//!
//!     bt = [ t0 t1 t2 t3 t4 t5 ... tn ct  0 ]
//!
//!     bu = [ u0 u1 u2 u3 u4 u5 ... un  0 cu ]
//!
//! We've added two new columns with sentinel values in bt and bu. This
//! will allow us to determine whether these two vectors are included in
//! any of the output vectors and in what proportions. (That's not the
//! only problem this solves. Our last set of vectors wasn't really a
//! basis, because we had n+2 vectors of degree n, so there were clearly
//! some redundancies in there.)
//!
//! We can identify the vector we're looking for by looking for cu in the
//! last slot of each vector in our reduced basis. Our hunch is that the
//! adjacent slot will contain -d*ct, and we can divide through by -ct to
//! recover d.
//!
//! Okay. To go any further, we need to dig into the nuts and bolts of
//! basis reduction. There are different strategies for finding a reduced
//! basis for a lattice, but we're going to focus on a simple and
//! efficient polynomial-time algorithm: Lenstra-Lenstra-Lovasz (LLL).
//!
//! Most people don't implement LLL. They use a library, of which there
//! are several excellent ones. NTL is a popular choice.
//!
//! For instructional purposes only, we're going to write our own.
//!
//! Here's some pseudocode:
//!
//!     function LLL(B, delta):
//!         B := copy(B)
//!         Q := gramschmidt(B)
//!
//!         function mu(i, j):
//!             v := B[i]
//!             u := Q[j]
//!             return (v*u) / (u*u)
//!
//!         n := len(B)
//!         k := 1
//!
//!         while k < n:
//!             for j in reverse(range(k)):
//!                 if abs(mu(k, j)) > 1/2:
//!                     B[k] := B[k] - round(mu(k, j))*B[j]
//!                     Q := gramschmidt(B)
//!
//!             if (Q[k]*Q[k]) >= (delta - mu(k, k-1)^2) * (Q[k-1]*Q[k-1]):
//!                 k := k + 1
//!             else:
//!                 B[k], B[k-1] := B[k-1], B[k]
//!                 Q := gramschmidt(B)
//!                 k := max(k-1, 1)
//!
//!         return B
//!
//! B is our input basis. Delta is a parameter such that 0.25 < delta <=
//! 1. You can just set it to 0.99 and forget about it.
//!
//! Gram-Schmidt is an algorithm to convert a basis into an equivalent
//! basis of mutually orthogonal (a fancy word for "perpendicular")
//! vectors. It's dead simple:
//!
//!     function proj(u, v):
//!         if u = 0:
//!             return 0
//!         return ((v*u) / (u*u)) * u
//!
//!     function gramschmidt(B):
//!         Q := []
//!         for i, v in enumerate(B):
//!             Q[i] := v - sum(proj(u, v) for u in Q[:i])
//!         return Q
//!
//! Proj finds the projection of v onto u. This is basically the part of v
//! going in the same "direction" as u. If u and v are orthogonal, this is
//! the zero vector. Gram-Schmidt orthogonalizes a basis by iterating over
//! the original and shaving off these projections.
//!
//! Back to LLL. The best way to get a sense for how and why it works is
//! to implement it and test it on some small examples with lots of debug
//! output. But basically: we walk up and down the basis B, comparing each
//! vector b against the orthogonalized basis Q. Whenever we find a vector
//! q in Q that mostly aligns with b, we shave off an integral
//! approximation of q's projection onto b. Remember that the lattice
//! deals in integral coefficients, and so must we. After each iteration,
//! we use some heuristics to decide whether we should move forward or
//! backward in B, whether we should swap some rows, etc.
//!
//! One more thing: the above description of LLL is very naive and
//! inefficient. It probably won't be fast enough for our purposes, so you
//! may need to optimize it a little. A good place to start would be not
//! recalculating the entire Q matrix on every update.
//!
//! Here's a test basis:
//!
//!     b1 = [  -2    0    2    0]
//!     b2 = [ 1/2   -1    0    0]
//!     b3 = [  -1    0   -2  1/2]
//!     b4 = [  -1    1    1    2]
//!
//! It reduces to this (with delta = 0.99):
//!
//!     b1 = [ 1/2   -1    0    0]
//!     b2 = [  -1    0   -2  1/2]
//!     b3 = [-1/2    0    1    2]
//!     b4 = [-3/2   -1    2    0]
//!
//! I forgot to mention: you'll want to write your implementation to work
//! on vectors of rationals. If you have infinite-precision floats,
//! those'll work too.
//!
//! All that's left is to tie up a few loose ends. First, how do we choose
//! our sentinel values ct and cu? This is kind of an implementation
//! detail, but we want to "balance" the size of the entries in our target
//! vector. And since we expect all of the other entries to be roughly
//! size q/2^l:
//!
//!     ct = 1/2^l
//!     cu = q/2^l
//!
//! Remember that ct will be multiplied by -d, and d is roughly the size
//! of q.
//!
//! Okay, you're finally ready to run the attack:
//!
//! 1. Generate your ECDSA secret key d.
//!
//! 2. Sign a bunch of messages using d and your biased nonce generator.
//!
//! 3. As the attacker, collect your (u, t) pairs. You can experiment with
//!    the amount. With an eight-bit nonce bias, I get good results with
//!    as few as 20 signatures. YMMV.
//!
//! 4. Stuff your values into a matrix and reduce it with LLL. Consider
//!    playing with some smaller matrices to get a sense for how long this
//!    will take to run.
//!
//! 5. In the reduced basis, find a vector with q/2^l as the final
//!    entry. There's a good chance it will have -d/2^l as the
//!    second-to-last entry. Extract d.

use crate::utils::*;

pub fn main() -> Result<()> {
    unimplemented!()
}
