use std::collections::BTreeSet;
use std::ops::Bound::Included;

use num_bigint::BigInt;

use crate::utils::*;

// Need some sort of intervals struct
#[derive(Debug, PartialEq, Clone)]
struct Interval {
    start: BigInt,
    end: BigInt,
}

impl Interval {
    pub fn new(start: &BigInt, end: &BigInt) -> Self {
        Self {
            start: start.clone(),
            end: end.clone(),
        }
    }
}

// Represents series of disjoint intervals
//
struct IntervalTree {
    lefts: BTreeSet<BigInt>,
    rights: BTreeSet<BigInt>,
}
impl Default for IntervalTree {
    fn default() -> Self {
        IntervalTree {
            lefts: Default::default(),
            rights: Default::default(),
        }
    }
}

impl IntervalTree {
    pub fn get_intervals(&self) -> Vec<Interval> {
        // Intervals are disjoint, so the ordering is the same
        self.lefts
            .iter()
            .zip(self.rights.iter())
            .map(|(x, y)| Interval {
                start: x.clone(),
                end: y.clone(),
            })
            .collect()
    }

    pub fn insert_interval(&mut self, interval: &Interval) {
        // There are four cases to consider:
        // 1. Interval is disjoint
        // 2. Interval overlaps one set on the left
        // 3. Interval overlaps one set on the right
        // 4. Interval joins two intervals

        // How does this play out? We start by taking lefts and rights and doing "split_off"
        // Imagine our intervals are (4,8) (11,13) (20,25)
        // And we wish to insert (x,y)
        // Our two BTreeSets are [4,11,20], [8,13,25]
        // We can find the elements which are included in the range defined by this
        //let left_pt: BigInt = &interval.start - 1;
        //let right_pt: BigInt = &interval.end + 1;

        // Count how many left points are inside interval
        let left_number = self
            .lefts
            .range((
                Included(&(interval.start.clone())),
                Included(&(interval.end.clone())),
            ))
            .count();
        let right_number = self
            .rights
            .range((
                Included(&(interval.start.clone())),
                Included(&(interval.end.clone())),
            ))
            .count();

        // There are three options here:
        // 1. They are equal, in which case our interval completely encompasses them and we can
        //    delete all of them and insert our new interval markers
        // 2. L = R+1, which means that we can delete all the lefts, and all of the rights, but
        //    only insert the leftmost point
        //    [ () () (  ]   )
        // 3. L+1 = R, which means that we can delete all the rights and all the lefts in the
        //    interval, and only insert the rightmost point
        // All of these cases delete all of them, so lets do that!
        let mut left_split = self
            .lefts
            .split_off(&interval.start)
            .split_off(&interval.end);
        self.lefts.append(&mut left_split);

        let mut left_split = self
            .rights
            .split_off(&interval.start)
            .split_off(&interval.end);
        self.rights.append(&mut left_split);

        // Now add the points back in which ought to be there
        match left_number == right_number {
            true => {
                self.lefts.insert(interval.start.clone());
                self.rights.insert(interval.end.clone());
            }
            false => match left_number < right_number {
                true => {
                    self.rights.insert(interval.end.clone());
                }
                false => {
                    self.lefts.insert(interval.start.clone());
                }
            },
        }

        // Finally, we do a quick check to "fuse" intervals
        // (    )[    ](     )
        // ->
        // (                 )
        // or any combination thereof
        let left_pt: BigInt = &interval.start - 1;
        if self.rights.remove(&left_pt) {
            self.lefts.remove(&interval.start);
        }
        let right_pt: BigInt = &interval.end + 1;
        if self.lefts.remove(&right_pt) {
            self.rights.remove(&interval.end);
        }
    }
}

pub fn main() -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use num_traits::FromPrimitive;

    use super::*;

    #[test]
    fn interval_tests() {
        let mut tree = IntervalTree::default();
        println!("Empty tree: {:?}", tree.get_intervals());
        assert_eq!(tree.get_intervals(), vec![]);
        let five_ten_int = Interval::new(
            &BigInt::from_i32(5).unwrap(),
            &BigInt::from_i32(10).unwrap(),
        );
        tree.insert_interval(&five_ten_int);
        assert_eq!(tree.get_intervals(), vec![five_ten_int.clone()]);
        let twelve_thirteen_int = Interval::new(
            &BigInt::from_i32(12).unwrap(),
            &BigInt::from_i32(13).unwrap(),
        );
        tree.insert_interval(&twelve_thirteen_int);
        assert_eq!(
            tree.get_intervals(),
            vec![five_ten_int, twelve_thirteen_int]
        );
        let eleven_fifteen_int = Interval::new(
            &BigInt::from_i32(11).unwrap(),
            &BigInt::from_i32(15).unwrap(),
        );
        tree.insert_interval(&eleven_fifteen_int);
        let five_fifteen_int = Interval::new(
            &BigInt::from_i32(5).unwrap(),
            &BigInt::from_i32(15).unwrap(),
        );
        assert_eq!(tree.get_intervals(), vec![five_fifteen_int]);
        let two_six_int =
            Interval::new(&BigInt::from_i32(2).unwrap(), &BigInt::from_i32(6).unwrap());
        tree.insert_interval(&two_six_int);
        let two_fifteen_int = Interval::new(
            &BigInt::from_i32(2).unwrap(),
            &BigInt::from_i32(15).unwrap(),
        );
        assert_eq!(tree.get_intervals(), vec![two_fifteen_int]);

        println!("Tree: {:?}", tree.get_intervals());
    }
}
