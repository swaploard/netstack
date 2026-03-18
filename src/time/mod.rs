//! Time primitives for the networking stack.
//!
//! Provides a lightweight `Instant` type used for timer management,
//! retransmission timeouts, and connection keepalives.

/// A point in time, represented as milliseconds since an arbitrary epoch.
///
/// This is stack-internal and does not depend on `std::time` so it can
/// work in `no_std` environments in the future.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant {
    millis: i64,
}

impl Instant {
    /// Create an instant from a millisecond timestamp.
    pub const fn from_millis(millis: i64) -> Self {
        Instant { millis }
    }

    /// Returns the time in milliseconds.
    pub const fn millis(&self) -> i64 {
        self.millis
    }

    /// Returns the duration in milliseconds since `earlier`.
    pub fn duration_since(&self, earlier: Instant) -> Duration {
        Duration::from_millis(self.millis.saturating_sub(earlier.millis))
    }
}

impl core::ops::Add<Duration> for Instant {
    type Output = Instant;
    fn add(self, rhs: Duration) -> Self::Output {
        Instant::from_millis(self.millis + rhs.millis)
    }
}

impl core::ops::Sub<Duration> for Instant {
    type Output = Instant;
    fn sub(self, rhs: Duration) -> Self::Output {
        Instant::from_millis(self.millis - rhs.millis)
    }
}

/// A duration of time in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Duration {
    millis: i64,
}

impl Duration {
    pub const ZERO: Duration = Duration { millis: 0 };

    /// Create a duration from milliseconds.
    pub const fn from_millis(millis: i64) -> Self {
        Duration { millis }
    }

    /// Create a duration from seconds.
    pub const fn from_secs(secs: i64) -> Self {
        Duration {
            millis: secs * 1000,
        }
    }

    /// Returns the duration in milliseconds.
    pub const fn millis(&self) -> i64 {
        self.millis
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instant_arithmetic() {
        let t0 = Instant::from_millis(1000);
        let t1 = t0 + Duration::from_millis(500);
        assert_eq!(t1.millis(), 1500);
        let d = t1.duration_since(t0);
        assert_eq!(d.millis(), 500);
    }

    #[test]
    fn test_duration_from_secs() {
        let d = Duration::from_secs(3);
        assert_eq!(d.millis(), 3000);
    }
}
