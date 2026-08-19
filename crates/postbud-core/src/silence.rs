//! Telling "nothing happened" apart from "nothing works".
//!
//! Every other check in this crate asks whether something that DID happen
//! was correct. These ask the opposite and harder question: whether
//! something that should have happened is missing. Harder because an empty
//! table is exactly what a healthy quiet week looks like, and exactly what
//! a broken pipe looks like.
//!
//! Both failures this exists for were real. The bounce pipe was configured
//! from the start and never ran once — every DSN was addressed to a
//! mailbox a person reads, `bounce_report` stayed empty, and nothing
//! anywhere said so. Aggregate reports sat unread in their mailbox for ten
//! days for the same reason. Neither produced an error. Both produced
//! silence, and silence is what nobody looks at.
//!
//! The rule that matters most here is knowing when NOT to speak. A monitor
//! that cries wolf over a quiet Tuesday teaches an operator to ignore it,
//! and is then worth less than nothing — so "we cannot tell" is a first
//! class answer here, kept deliberately distinct from "healthy".

use serde::Serialize;

/// How many sends must have happened before zero bounces means anything.
///
/// Even a half-percent bounce rate makes zero bounces in 500 messages
/// roughly a one-in-twelve coincidence; in 65 messages it is entirely
/// ordinary. Below this the honest answer is that we cannot tell, which is
/// why this is a named constant with a reason rather than a number
/// somebody liked the look of.
pub const BOUNCE_EVIDENCE_SENDS: i64 = 500;

/// Aggregate reports arrive daily, per receiver, whatever the volume — so
/// unlike bounces their absence is meaningful even for a small sender.
/// One missed day is a slow receiver. Three is the mailbox, the
/// credentials, or the poller.
pub const DMARC_STALE_DAYS: i64 = 3;

/// What the evidence supports. Serialized for the admin surface, which
/// displays it and does nothing else with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Signal {
    /// Evidence arrived: the path works.
    Healthy { detail: String },
    /// Not enough has happened to distinguish working from broken. NOT a
    /// problem, and deliberately not folded into `Healthy` — reporting
    /// health on the strength of no evidence is exactly how a monitor
    /// becomes decoration.
    Inconclusive { detail: String },
    /// Silence where there should have been noise.
    Silent { detail: String },
}

impl Signal {
    pub fn is_silent(&self) -> bool {
        matches!(self, Signal::Silent { .. })
    }
}

/// Is the bounce path carrying anything?
///
/// A single bounce proves the whole chain — envelope sender, relay
/// routing, the pipe, ingestion — so any bounce at all is health. The
/// interesting case is zero, and whether zero means anything depends
/// entirely on how much was sent.
pub fn bounce_signal(sent: i64, bounces: i64) -> Signal {
    if bounces > 0 {
        return Signal::Healthy {
            detail: format!("{bounces} recorded — the DSN path is carrying"),
        };
    }
    if sent < BOUNCE_EVIDENCE_SENDS {
        return Signal::Inconclusive {
            detail: format!(
                "{sent} sent; below {BOUNCE_EVIDENCE_SENDS} a clean sheet is ordinary, \
                 so this cannot yet tell a working path from a broken one"
            ),
        };
    }
    Signal::Silent {
        detail: format!(
            "{sent} sent and not one bounce recorded. At this volume that is far more \
             likely to be a broken return path than perfect addresses — check that the \
             envelope sender resolves to a mailbox routed into the bounce pipe"
        ),
    }
}

/// Are aggregate reports still arriving?
///
/// `newest_age_days` is the age of the most recent report held, which is
/// the only thing that distinguishes "the poller stopped" from "nobody has
/// written to us yet".
pub fn dmarc_signal(newest_age_days: Option<i64>) -> Signal {
    let Some(age) = newest_age_days else {
        return Signal::Inconclusive {
            detail: "no reports have ever arrived; the mailbox poller may not be \
                     configured, or no receiver has been asked to report yet"
                .into(),
        };
    };
    if age <= DMARC_STALE_DAYS {
        return Signal::Healthy {
            detail: match age {
                0 => "newest report arrived today".into(),
                1 => "newest report arrived yesterday".into(),
                n => format!("newest report is {n} days old"),
            },
        };
    }
    Signal::Silent {
        detail: format!(
            "newest report is {age} days old. Receivers send daily, so a gap this long \
             is the mailbox, the credentials or the poller rather than the receivers"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The case this whole module exists to get right.
    ///
    /// 66 messages and no bounces is what a small sender with good
    /// addresses looks like. Calling that broken would be wrong, and
    /// calling it healthy would be a guess — the honest answer is that
    /// there is not enough evidence either way.
    #[test]
    fn a_small_sender_with_no_bounces_is_not_accused() {
        let signal = bounce_signal(66, 0);
        assert!(matches!(signal, Signal::Inconclusive { .. }), "{signal:?}");
        assert!(!signal.is_silent());
    }

    /// ...and the same clean sheet at real volume is the alarm. This is
    /// the shape the broken pipe would have had.
    #[test]
    fn a_busy_sender_with_no_bounces_is_the_alarm() {
        assert!(bounce_signal(5_000, 0).is_silent());
        // Exactly at the threshold counts: the constant is the point at
        // which silence starts to mean something.
        assert!(bounce_signal(BOUNCE_EVIDENCE_SENDS, 0).is_silent());
        assert!(!bounce_signal(BOUNCE_EVIDENCE_SENDS - 1, 0).is_silent());
    }

    /// One bounce proves the entire chain, so volume stops mattering.
    #[test]
    fn any_bounce_at_all_is_health() {
        assert!(matches!(bounce_signal(1, 1), Signal::Healthy { .. }));
        assert!(matches!(bounce_signal(100_000, 1), Signal::Healthy { .. }));
    }

    /// Never having received a report is not the same as having stopped.
    /// An installation that collects no reports is not broken.
    #[test]
    fn never_having_had_a_report_is_not_an_alarm() {
        let signal = dmarc_signal(None);
        assert!(matches!(signal, Signal::Inconclusive { .. }), "{signal:?}");
    }

    #[test]
    fn reports_still_arriving_are_health() {
        for age in 0..=DMARC_STALE_DAYS {
            assert!(
                matches!(dmarc_signal(Some(age)), Signal::Healthy { .. }),
                "{age} days should be healthy"
            );
        }
    }

    /// Reports arrive daily whatever the volume, so a gap is meaningful
    /// even for a sender too small to judge on bounces.
    #[test]
    fn a_gap_in_daily_reports_is_the_alarm() {
        assert!(dmarc_signal(Some(DMARC_STALE_DAYS + 1)).is_silent());
        assert!(dmarc_signal(Some(30)).is_silent());
    }
}
