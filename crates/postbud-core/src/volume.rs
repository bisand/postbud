//! Noticing that a tenant's sending changed shape.
//!
//! A per-tenant rate limit bounds the damage from a leaked key. This is
//! the other half: noticing, so the key can be revoked and the damage
//! stopped rather than merely capped. The two are not alternatives, but
//! only one of them can be built before there is a baseline to set it
//! from — and only one of them can never block an invoice run.
//!
//! Which is the constraint that shapes everything here. Transactional
//! senders are BURSTY by nature: an invoicing system is quiet for a month
//! and then sends a month's invoices in an hour, and that is the system
//! working. A signal that calls it an incident gets turned off, and then
//! it is not there on the day it matters.
//!
//! So the same discipline as [`crate::silence`]: an absolute floor before
//! a ratio is allowed to mean anything, a baseline that a single past
//! spike cannot inflate, and "not enough evidence" as a real answer.

use serde::Serialize;

/// Messages in a day below which no multiple is interesting. Two becoming
/// twenty is a tenfold increase and eighteen messages; nothing has gone
/// wrong that anyone needs to be told about. This one gate also disposes
/// of the awkward cases — a brand new tenant, and a baseline of zero,
/// where every ratio is infinite and none of them is evidence.
pub const MIN_DAILY: i64 = 50;

/// How many times its own typical day a tenant must exceed. Deliberately
/// blunt: the point is catching a key sending thousands, not policing
/// growth. Anything tighter would need a baseline nobody has yet.
pub const SPIKE_MULTIPLE: f64 = 10.0;

/// Days of history before a typical day means anything.
pub const MIN_HISTORY_DAYS: i64 = 7;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Volume {
    Normal { detail: String },
    Inconclusive { detail: String },
    Unusual { detail: String },
}

impl Volume {
    pub fn is_unusual(&self) -> bool {
        matches!(self, Volume::Unusual { .. })
    }
}

/// Compare a tenant's last day against its own typical day.
///
/// `typical_daily` is a MEDIAN, not a mean, and the difference matters: a
/// mean is dragged upwards by exactly the bursts this has to see past. A
/// tenant that sends three a day and five hundred at month end has a mean
/// near forty, so a leaked key sending three hundred a day would look
/// unremarkable. Its median is three.
pub fn judge(recent_24h: i64, typical_daily: f64, history_days: i64) -> Volume {
    // The floor first, and on its own. Below it nothing else is worth
    // computing, and saying so is more honest than a verdict drawn from
    // a handful of messages.
    if recent_24h < MIN_DAILY {
        return Volume::Inconclusive {
            detail: format!(
                "{recent_24h} in the last day; under {MIN_DAILY} no multiple of a \
                 typical day is worth reporting"
            ),
        };
    }
    if history_days < MIN_HISTORY_DAYS {
        return Volume::Inconclusive {
            detail: format!(
                "{recent_24h} in the last day, but only {history_days} day(s) of \
                 history — there is no typical day to compare against yet"
            ),
        };
    }

    let threshold = typical_daily * SPIKE_MULTIPLE;
    if recent_24h as f64 >= threshold.max(MIN_DAILY as f64) {
        return Volume::Unusual {
            detail: format!(
                "{recent_24h} in the last day against a typical {typical_daily:.0}. \
                 If this is not a run somebody started, treat the key as leaked: \
                 deactivate the tenant or rotate its key, which stops it rather \
                 than capping it"
            ),
        };
    }
    Volume::Normal {
        detail: format!("{recent_24h} in the last day, typical {typical_daily:.0}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape of this installation today. Everything is small, and a
    /// small number cannot be an incident however it is divided.
    #[test]
    fn small_traffic_is_never_an_incident() {
        // Sixteen against a typical one: a sixteenfold jump, and nothing.
        assert!(!judge(16, 1.0, 30).is_unusual());
        assert!(!judge(49, 0.0, 30).is_unusual());
    }

    /// A leaked key is what this is for.
    #[test]
    fn a_key_sending_thousands_is_flagged() {
        let v = judge(5_000, 3.0, 30);
        assert!(v.is_unusual());
        let Volume::Unusual { detail } = v else {
            unreachable!()
        };
        // It must say what ENDS it, not merely that it happened.
        assert!(detail.contains("rotate its key"));
    }

    /// The reason the baseline is a median.
    ///
    /// A tenant sending three a day with one five-hundred month end has a
    /// MEAN near forty; three hundred a day would then be under eight
    /// times it and pass unnoticed. Against its median of three it is a
    /// hundredfold.
    #[test]
    fn a_past_burst_does_not_hide_the_next_one() {
        assert!(judge(300, 3.0, 30).is_unusual());
        // ...and the same figures against the mean that burst produces.
        assert!(!judge(300, 40.0, 30).is_unusual());
    }

    /// Growth is not an incident. A tenant doing three times its usual
    /// volume is having a busy day, and a signal that says otherwise gets
    /// switched off before the day it is needed.
    #[test]
    fn ordinary_growth_is_not_flagged() {
        assert!(!judge(300, 100.0, 30).is_unusual());
        assert!(matches!(judge(300, 100.0, 30), Volume::Normal { .. }));
    }

    /// A new tenant has no typical day, and its first real send must not
    /// be reported as an anomaly.
    #[test]
    fn a_new_tenant_has_nothing_to_compare_against() {
        assert!(matches!(judge(500, 0.0, 2), Volume::Inconclusive { .. }));
    }

    /// A quiet tenant that wakes up must clear the floor on its own
    /// merits rather than on a division by zero.
    #[test]
    fn a_zero_baseline_still_needs_real_volume() {
        assert!(!judge(20, 0.0, 30).is_unusual());
        assert!(judge(500, 0.0, 30).is_unusual());
    }
}
