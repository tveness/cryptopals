//! 64. Key-Recovery Attacks on GCM with a Truncated MAC
//!
//! This one is my favorite.
//!
//! It's somewhat common to use a truncated MAC tag. For instance, you
//! might be authenticating with HMAC-SHA256 and shorten the tag to 128
//! bits. The idea is that you can save some bandwidth or storage and
//! still have an acceptable level of security.
//!
//! This is a totally reasonable thing to want.
//!
//! In some protocols, you might take this to the extreme. If two parties
//! are exchanging lots of small packets, and the value of forging any one
//! packet is pretty low, they might use a 16-bit tag and expect 16 bits
//! of security.
//!
//! In GCM, this is a disaster.
//!
//! To see how, we'll first review the GCM MAC function. We make a
//! calculation like this:
//!
//!     t = s + c1*h + c2*h^2 + c3*h^3 + ... + cn*h^n
//!
//! We're making some notational changes here for convenience; most
//! notably, we using one-based indexing. The c1 block encodes the length,
//! and [c2, cn] are blocks of ciphertext.
//!
//! We'll also ignore the possibility of AD blocks here, since they don't
//! matter too much for our purposes.
//!
//! Recall that our coefficients (and our authentication key h) are
//! elements in GF(2^128). We've seen a few different representations,
//! namely polynomials in GF(2) and unsigned integers. To this we'll add
//! one more: a 128-degree vector over GF(2). It's basically just a bit
//! vector; not so different from either of our previous representations,
//! but we want to get our heads in linear algebra mode.
//!
//! The key concept we want to explore here is that certain operations in
//! GF(2^128) are linear.
//!
//! One of them is multiplication by a constant. Suppose we have this
//! function:
//!
//!     f(y) = c*y
//!
//! With c and y both elements of GF(2^128). This function is linear in
//! the bits of y. That means that this function is equivalent:
//!
//!     g(y) = c*y[0] + c*y[1] + c*y[2] + ... + c*y[127]
//!
//! Any linear function can be represented by matrix multiplication. So if
//! we think of y as a vector, we can construct a matrix Mc such that:
//!
//!     Mc*y = f(y) = c*y
//!
//! To construct Mc, just calculate c*1, c*x, c*x^2, ..., c*x^127, convert
//! each product to a vector, and let the vectors be the columns of your
//! matrix. You can verify by performing the matrix multiplication against
//! y and checking the result. I'm going to assume you either know how
//! matrix multiplication works or have access to Wikipedia to look it up.
//!
//! Squaring is also linear. This is because (a + b)^2 = a^2 + b^2 in
//! GF(2^128). Again, this means we can replace this function:
//!
//!     f(y) = y^2
//!
//! With a matrix multiplication. Again, compute 1^2, x^2, (x^2)^2, ...,
//! (x^127)^2, convert the results to vectors, and make them your
//! columns. Then verify that:
//!
//!     Ms*y = f(y) = y^2
//!
//! Okay, let's put these matrices on the back burner for now. To forge a
//! ciphertext c', we'll start with a valid ciphertext c and flip some
//! bits, hoping that:
//!
//!     sum(ci * h^i) = sum(ci' * h^i)
//!
//! Another way to write this is:
//!
//!     sum((ci - ci') * h^i) = 0
//!
//! If we let ei = ci - ci', we can simplify this:
//!
//!     sum(ei * h^i) = 0
//!
//! Note that if we leave a block unmolested, then ei = ci - ci' =
//! 0. We're going to leave most ei = 0. In fact, we're only going to flip
//! bits in blocks di = e(2^i). These are blocks d0, d1, d2, ..., dn (note
//! that we're back to zero-based indexing) such that:
//!
//!     sum(di * h^(2^i)) = 0
//!
//! We hope it equals zero, anyway. Maybe it's better to say:
//!
//!     sum(di * h^(2^i)) = e
//!
//! Where e is some error polynomial. In other words, the difference in
//! the MAC tag induced by our bit-flipping.
//!
//! At this point, we'll recall the matrix view. Recall that
//! multiplications by a constant and squaring operations are both
//! linear. That means we can rewrite the above equation as a linear
//! operation on h:
//!
//!     sum(Mdi * Ms^i * h) = e
//!     sum(Mdi * Ms^i) * h = e
//!
//!     Ad = sum(Mdi * Ms^i)
//!
//!     Ad * h = e
//!
//! We want to find an Ad such that Ad * h = 0.
//!
//! Let's think about how the bits in the vector e are calculated. This
//! just falls out of the basic rules of matrix multiplication:
//!
//!     e[0] = Ad[0] * h
//!     e[1] = Ad[1] * h
//!     e[2] = Ad[2] * h
//!     e[3] = Ad[3] * h
//!     ...
//!
//! In other words, e[i] is the inner product of row i of Ad with h. If we
//! can force rows of Ad to zero, we can force terms of the error
//! polynomial to zero. Every row we force to zero will basically double
//! our chances of a forgery.
//!
//! Suppose the MAC is 16 bits. If we can flip bits and force eight rows
//! of Ad to zero, that's eight bits of the MAC we know are right. We can
//! flip whatever bits are left over with a 2^-8 chance of a forgery, way
//! better than the expected 2^-16!
//!
//! It turns out to be really easy to force rows of Ad to zero. Ad is the
//! sum of a bunch of linear operations. That means we can simply
//! determine which bits of d0, d1, ..., dn affect which bits of Ad and
//! flip them accordingly.
//!
//! Actually, let's leave d0 alone. That's the block that encodes the
//! ciphertext length. Things could get tricky pretty quickly if we start
//! messing with it.
//!
//! We still have d1, ..., dn to play with. That means n*128 bits we can
//! flip. Since the rows of Ad are each 128 bits, we'll have to settle for
//! forcing n-1 of them to zero. We need some bits left over to play with.
//!
//! Check the strategy: we'll build a dependency matrix T with n*128
//! columns and (n-1)*128 rows. Each column represents a bit we can flip,
//! and each row represents a cell of Ad (reading left-to-right,
//! top-to-bottom). The cells where they intersect record whether a
//! particular free bit affects a particular bit of Ad.
//!
//! Iterate over the columns. Build the hypothetical Ad you'd get by
//! flipping only the corresponding bit. Iterate over the first (n-1)*128
//! cells of Ad and set the corresponding cells in this column of T.
//!
//! After doing this for each column, T will be full of ones and
//! zeros. We're looking for sets of bit flips that will zero out those
//! first n-1 rows. In other words, we're looking for solutions to this
//! equation:
//!
//!     T * d = 0
//!
//! Where d is a vector representing all n*128 bits you have to play with.
//!
//! If you know a little bit of linear algebra, you'll know that what we
//! really want to find is a basis for N(T), the null space of T. The null
//! space is exactly that set of vectors that solve the equation
//! above. Just what we're looking for. Recall that a basis is a minimal
//! set of vectors whose linear combinations span the whole space. So if
//! we find a basis for N(T), we can just take random combinations of its
//! vectors to get viable candidates for d.
//!
//! Finding a basis for the null space is not too hard. What you want to
//! do is transpose T (i.e. flip it across its diagonal) and find the
//! reduced row echelon form using Gaussian elimination. Now perform the
//! same operations on an identity matrix of size n*128. The rows that
//! correspond to the zero rows in the reduced row echelon form of T
//! transpose form a basis for N(T).
//!
//! Gaussian elimination is pretty simple; you can more or less figure it
//! out yourself once you know what it's supposed to do.
//!
//! Now that we have a basis for N(T), we're ready to start forging
//! messages. Take a random vector from N(T) and decode it to a bunch of
//! bit flips in your known good ciphertext C. (Remember that you'll be
//! flipping bits only in the blocks that are multiplied by h^(2*i) for
//! some i.) Send the adjusted message C' to the oracle and see if it
//! passes authentication. If it fails, generate a new vector and try
//! again.
//!
//! If it succeeds, we've gained more than just an easy forgery. Examine
//! your matrix Ad. It should be a bunch of zero rows followed by a bunch
//! of nonzero rows. We care about the nonzero rows corresponding to the
//! bits of the tag. So if your tag is 16 bits, and you forced eight bits
//! to zero, you should have eight nonzero rows of interest.
//!
//! Pick those rows out and stuff them in a matrix of their own. Call it,
//! I don't know, K. Here's something neat we know about K:
//!
//!     K * h = 0
//!
//! In other words, h is in the null space of K! In our example, K is an
//! 8x128 matrix. Assuming all its rows are independent (none of them is a
//! combination of any of the others), N(K) is a 120-dimensional subspace
//! of the larger 128-dimensional space. Since we know h is in there, the
//! range of possible values for h went from 2^128 to 2^120.
//!
//! 2^120 is still a lot of values, but hey - it's a start.
//!
//! If we can produce more forgeries, we can find more vectors to add to
//! K, reducing the range of values further and further. And check this
//! out: our newfound knowledge of h is going to make the next forgery
//! even easier. Find a basis for N(K) and put the vectors in the columns
//! of a matrix. Call it X. Now we can rewrite h like this:
//!
//!     h = X * h'
//!
//! Where h' is some unknown 120-bit vector. Now instead of saying:
//!
//!     Ad * h = e
//!
//! We can say:
//!
//!     Ad * X * h' = e
//!
//! Whereas Ad is a 128x128 matrix, X is 128x120. And Ad * X is also
//! 128x120. Instead of zeroing out 128-degree row vectors, now we can
//! zero out 120-degree vectors. Since we still have the same number of
//! bits to play with, we can (maybe) zero out more rows than before. The
//! general picture is that if we have n*128 bits to play with, we can
//! zero out (n*128) / (ncols(X)) rows. Just remember to leave at least
//! one nonzero row in each attempt; otherwise you won't learn anything
//! new.
//!
//! So: start over and build a new T matrix, but this time to nullify rows
//! of Ad * X. Forge another message and harvest some new linear equations
//! on h. Stuff them in K and recalculate X.
//!
//! Lather, rinse, repeat.
//!
//! The endgame comes when K has 127 linearly independent rows. N(K) will
//! be a 1-dimensional subspace containing exactly one nonzero vector, and
//! that vector will be h.
//!
//! Let's try it out:
//!
//! 1. Build a toy system with a 32-bit MAC. This is the smallest tag
//!    length NIST defines in the GCM specification.
//!
//! 2. Generate valid messages of 2^17 blocks for the attacker to play
//!    with.
//!
//! 3. As the attacker, build your matrices, forge messages, and recover
//!    the key. You should be able to zero out 16 bits of each tag to
//!    start, and you'll only gain leverage from there.

use crate::utils::*;

pub fn main() -> Result<()> {
    unimplemented!()
}
