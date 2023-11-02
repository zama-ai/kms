use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

use crate::{execution::party::Role, poly::Ring, value};

/// Generic structure for shares with non-interactive methods possible to carry out on shares.
#[derive(Clone, Debug, Hash, PartialEq, Eq, Copy)]
pub struct Share<R>
where
    R: Ring + std::convert::From<value::Value> + Send + Sync,
    value::Value: std::convert::From<R>,
{
    value: R,
    owner: Role,
}
impl<R: Ring + std::convert::From<value::Value> + Send + Sync> Share<R>
where
    value::Value: std::convert::From<R>,
{
    /// Construct a new share based on the actual share and the owner.
    /// I.e. this is a non-interactive and should not be mistaken for an input phase in MPC.
    pub fn new(owner: Role, value: R) -> Self {
        Self { value, owner }
    }

    /// Get the actual share as a ring element
    pub fn value(&self) -> R {
        self.value
    }

    /// Get the designated owner of the share
    pub fn owner(&self) -> Role {
        self.owner
    }
}
impl<R: Ring + std::convert::From<value::Value> + Send + Sync> Add for Share<R>
where
    value::Value: std::convert::From<R>,
{
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
impl<R: Ring + std::convert::From<value::Value> + Send + Sync> AddAssign for Share<R>
where
    value::Value: std::convert::From<R>,
{
    fn add_assign(&mut self, rhs: Self) {
        if self.owner != rhs.owner {
            tracing::warn!("Trying to add two shares with different owners. This will always result in an incorrect share");
        }
        self.value += rhs.value;
    }
}
impl<R: Ring + std::convert::From<value::Value> + Send + Sync> Add<R> for Share<R>
where
    value::Value: std::convert::From<R>,
{
    type Output = Share<R>;
    fn add(self, other: R) -> Self::Output {
        Self {
            value: self.value + other,
            owner: self.owner,
        }
    }
}
impl<R: Ring + std::convert::From<value::Value> + Send + Sync> AddAssign<R> for Share<R>
where
    value::Value: std::convert::From<R>,
{
    fn add_assign(&mut self, other: R) {
        self.value += other;
    }
}

impl<R: Ring + std::convert::From<value::Value> + Send + Sync> Sub for Share<R>
where
    value::Value: std::convert::From<R>,
{
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
impl<R: Ring + std::convert::From<value::Value> + Send + Sync> SubAssign for Share<R>
where
    value::Value: std::convert::From<R>,
{
    fn sub_assign(&mut self, rhs: Self) {
        if self.owner != rhs.owner {
            tracing::warn!("Trying to subtract two shares with different owners. This will always result in an incorrect share");
        }
        self.value -= rhs.value;
    }
}
impl<R: Ring + std::convert::From<value::Value> + Send + Sync> Sub<R> for Share<R>
where
    value::Value: std::convert::From<R>,
{
    type Output = Share<R>;
    fn sub(self, rhs: R) -> Self::Output {
        Self {
            value: self.value - rhs,
            owner: self.owner,
        }
    }
}
impl<R: Ring + std::convert::From<value::Value> + Send + Sync> SubAssign<R> for Share<R>
where
    value::Value: std::convert::From<R>,
{
    fn sub_assign(&mut self, rhs: R) {
        self.value -= rhs;
    }
}
impl<R: Ring + std::convert::From<value::Value> + Send + Sync> Mul<R> for Share<R>
where
    value::Value: std::convert::From<R>,
{
    type Output = Share<R>;
    fn mul(self, rhs: R) -> Self::Output {
        Self {
            value: self.value * rhs,
            owner: self.owner,
        }
    }
}
impl<R: Ring + std::convert::From<value::Value> + Send + Sync> MulAssign<R> for Share<R>
where
    value::Value: std::convert::From<R>,
{
    fn mul_assign(&mut self, rhs: R) {
        self.value *= rhs;
    }
}
#[cfg(test)]
mod tests {
    use std::num::Wrapping;

    use crate::{
        execution::{online::share::Share, party::Role},
        residue_poly::ResiduePoly,
        Z128,
    };

    #[test]
    fn op_overload() {
        let share = Share::new(Role(1), ResiduePoly::<Z128>::from_scalar(Wrapping(42)));
        let one = ResiduePoly::<Z128>::from_scalar(Wrapping(1));
        let two = ResiduePoly::<Z128>::from_scalar(Wrapping(2));
        let res = share * two + one - two;
        assert_eq!(res.value(), ResiduePoly::<Z128>::from_scalar(Wrapping(83)));
        let mut new_share = share;
        new_share += new_share;
        assert_eq!(share * two, new_share);
        new_share -= share;
        assert_eq!(share, new_share);
    }
}
