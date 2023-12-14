use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

use crate::{algebra::structure_traits::Ring, execution::runtime::party::Role};

/// Generic structure for shares with non-interactive methods possible to carry out on shares.
#[derive(Clone, Debug, Hash, PartialEq, Eq, Copy)]
pub struct Share<Z>
where
    Z: Ring,
{
    value: Z,
    owner: Role,
}
impl<Z: Ring> Share<Z> {
    /// Construct a new share based on the actual share and the owner.
    /// I.e. this is a non-interactive and should not be mistaken for an input phase in MPC.
    pub fn new(owner: Role, value: Z) -> Self {
        Self { value, owner }
    }

    /// Get the actual share as a ring element
    pub fn value(&self) -> Z {
        self.value
    }

    /// Get the designated owner of the share
    pub fn owner(&self) -> Role {
        self.owner
    }
}
impl<Z: Ring> Add for Share<Z> {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        if self.owner != other.owner {
            tracing::warn!("Trying to add two shares with different owners. This will always result in an incorrect share");
        }
        Self {
            value: self.value + other.value,
            owner: self.owner,
        }
    }
}
impl<Z: Ring> AddAssign for Share<Z> {
    fn add_assign(&mut self, rhs: Self) {
        if self.owner != rhs.owner {
            tracing::warn!("Trying to add two shares with different owners. This will always result in an incorrect share");
        }
        self.value += rhs.value;
    }
}
impl<Z: Ring> Add<Z> for Share<Z> {
    type Output = Share<Z>;
    fn add(self, other: Z) -> Self::Output {
        Self {
            value: self.value + other,
            owner: self.owner,
        }
    }
}
impl<Z: Ring> AddAssign<Z> for Share<Z> {
    fn add_assign(&mut self, other: Z) {
        self.value += other;
    }
}

impl<Z: Ring> Sub for Share<Z> {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        if self.owner != other.owner {
            tracing::warn!("Trying to subtract two shares with different owners. This will always result in an incorrect share");
        }
        Self {
            value: self.value - other.value,
            owner: self.owner,
        }
    }
}
impl<Z: Ring> SubAssign for Share<Z> {
    fn sub_assign(&mut self, rhs: Self) {
        if self.owner != rhs.owner {
            tracing::warn!("Trying to subtract two shares with different owners. This will always result in an incorrect share");
        }
        self.value -= rhs.value;
    }
}
impl<Z: Ring> Sub<Z> for Share<Z> {
    type Output = Share<Z>;
    fn sub(self, rhs: Z) -> Self::Output {
        Self {
            value: self.value - rhs,
            owner: self.owner,
        }
    }
}
impl<Z: Ring> SubAssign<Z> for Share<Z> {
    fn sub_assign(&mut self, rhs: Z) {
        self.value -= rhs;
    }
}
impl<Z: Ring> Mul<Z> for Share<Z> {
    type Output = Share<Z>;
    fn mul(self, rhs: Z) -> Self::Output {
        Self {
            value: self.value * rhs,
            owner: self.owner,
        }
    }
}
impl<Z: Ring> MulAssign<Z> for Share<Z> {
    fn mul_assign(&mut self, rhs: Z) {
        self.value *= rhs;
    }
}
#[cfg(test)]
mod tests {
    use std::num::Wrapping;

    use crate::{
        algebra::residue_poly::ResiduePoly128,
        execution::{runtime::party::Role, sharing::share::Share},
    };

    #[test]
    fn op_overload() {
        let share = Share::new(
            Role::indexed_by_one(1),
            ResiduePoly128::from_scalar(Wrapping(42)),
        );
        let one = ResiduePoly128::from_scalar(Wrapping(1));
        let two = ResiduePoly128::from_scalar(Wrapping(2));
        let res = share * two + one - two;
        assert_eq!(res.value(), ResiduePoly128::from_scalar(Wrapping(83)));
        let mut new_share = share;
        new_share += new_share;
        assert_eq!(share * two, new_share);
        new_share -= share;
        assert_eq!(share, new_share);
    }
}
