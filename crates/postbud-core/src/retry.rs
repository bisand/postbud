//! The retry schedule.
//!
//! This exists because of a specific, measured failure mode. The in-app
//! retry loops postbud replaces typically retry a failed handoff on a
//! schedule like `[1s, 5s, 30s, 60s, 120s]` and give up after five
//! attempts — a total window of a few minutes, after which the message
//! vanishes with at most an advisory that nothing consumes.
//!
//! That window is fine when the transport is a hosted API that never
//! reboots. It is not fine when the transport is a single VM that gets
//! kernel updates: any outage longer than four minutes destroys invoices
//! silently. postbud persists on accept and retries across days, which is
//! the whole reason it sits in front of the relay.
//!
//! The schedule is deliberately front-loaded — most relay failures are a
//! restart that resolves in seconds — and then spreads out, because after
//! an hour the cause is something a human has to fix.

use std::time::Duration;

const MINUTE: u64 = 60;
const HOUR: u64 = 60 * MINUTE;

/// Delay before attempt N+1, indexed by the number of attempts already
/// made. Total span: just over two days.
pub const SCHEDULE: [u64; 9] = [
    MINUTE, // a relay restart
    5 * MINUTE,
    15 * MINUTE,
    HOUR,
    3 * HOUR,
    6 * HOUR,
    12 * HOUR,
    24 * HOUR,
    24 * HOUR, // ~49 h total before we stop
];

/// How long to wait before the next attempt, given how many attempts have
/// already been made. `None` means the message is dead: no attempt is
/// scheduled, and the failure becomes visible rather than silent.
pub fn backoff(attempts_made: u32) -> Option<Duration> {
    SCHEDULE
        .get(attempts_made as usize)
        .map(|secs| Duration::from_secs(*secs))
}

/// Total time a message may spend trying before it is given up on.
pub fn total_window() -> Duration {
    Duration::from_secs(SCHEDULE.iter().sum())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_then_ends() {
        assert_eq!(backoff(0), Some(Duration::from_secs(60)));
        assert_eq!(backoff(3), Some(Duration::from_secs(3600)));
        assert_eq!(backoff(SCHEDULE.len() as u32), None);
    }

    #[test]
    fn schedule_is_monotonic() {
        for pair in SCHEDULE.windows(2) {
            assert!(pair[1] >= pair[0], "backoff must never shrink: {pair:?}");
        }
    }

    /// The point of the crate. If this ever drops below a day, someone has
    /// reintroduced the failure mode postbud was built to remove.
    #[test]
    fn retry_window_survives_an_overnight_outage() {
        assert!(
            total_window() >= Duration::from_secs(24 * HOUR),
            "a relay outage must not destroy mail overnight"
        );
    }
}
