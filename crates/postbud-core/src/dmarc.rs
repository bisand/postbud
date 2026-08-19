//! DMARC aggregate report parsing (RFC 7489 Appendix C).
//!
//! Aggregate reports are the receiver's side of the story. The sending
//! domain registry says what DNS *should* carry and [`crate::dnscheck`]
//! says what it *does* carry; only these say what a receiver actually
//! concluded when the mail arrived. That is the one failure mode postbud
//! cannot otherwise see: a message quarantined at the far end is still a
//! clean `250 Ok: queued as ...` from the relay, so nothing in
//! `delivery_attempt` or `bounce_report` will ever record it.
//!
//! Everything here is a byte transform — no filesystem, no network — so
//! the same code serves a file on disk and an IMAP attachment later.
//!
//! **Reports are evidence, never instructions.** Anyone on the internet
//! can send a report to the address named in a `rua=` tag, claiming
//! whatever they like about any domain. Nothing parsed here may drive
//! suppression, domain status, or any other automatic action; it is
//! diagnostic material for a human, attributed to whoever claimed it.

use serde::{Deserialize, Serialize};

/// Refuse anything larger than this once decompressed. Reports of real
/// traffic run to a few kilobytes; a "report" that expands to tens of
/// megabytes is a decompression bomb, not a busy day.
pub const MAX_UNCOMPRESSED: usize = 32 * 1024 * 1024;

/// A zip carrying more than this many members is not a DMARC report.
pub const MAX_ARCHIVE_MEMBERS: usize = 16;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("report is larger than {MAX_UNCOMPRESSED} bytes uncompressed")]
    TooLarge,
    #[error("archive carries more than {MAX_ARCHIVE_MEMBERS} members")]
    TooManyMembers,
    #[error("document declares a DOCTYPE or ENTITY")]
    Doctype,
    #[error("no XML document in the attachment")]
    Empty,
    #[error("unreadable archive: {0}")]
    Archive(String),
    #[error("unreadable XML: {0}")]
    Xml(String),
    /// Structurally valid XML that is not an aggregate report.
    #[error("not a DMARC aggregate report: {0}")]
    NotAReport(&'static str),
}

/// One aggregate report: a single reporter's account of one time window
/// for one policy domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The reporting organisation's own name for itself. Untrusted, and
    /// shown as an attribution rather than as a fact.
    pub org_name: String,
    pub email: Option<String>,
    /// Unique per reporter. With `org_name` this is the dedupe key: the
    /// same report is delivered more than once often enough to matter.
    pub report_id: String,
    /// Window, as UNIX seconds, exactly as reported.
    pub begin: i64,
    pub end: i64,
    /// The domain whose policy was applied.
    pub domain: String,
    pub p: Option<String>,
    pub sp: Option<String>,
    pub pct: Option<i32>,
    pub adkim: Option<String>,
    pub aspf: Option<String>,
    pub records: Vec<Record>,
}

/// One source's traffic within a report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub source_ip: String,
    pub count: i64,
    pub disposition: String,
    /// The *aligned* DKIM result — the DMARC verdict, not the bare
    /// signature check. The distinction is the whole point: a message can
    /// carry a perfectly valid signature for someone else's domain and
    /// still fail DMARC, which is what `auth` records separately.
    pub dkim_aligned: String,
    /// The aligned SPF result, with the same caveat.
    pub spf_aligned: String,
    pub header_from: String,
    pub auth: AuthResults,
    pub reasons: Vec<Reason>,
}

impl Record {
    /// DMARC passes on either aligned mechanism; one is enough.
    pub fn passed(&self) -> bool {
        self.dkim_aligned == "pass" || self.spf_aligned == "pass"
    }
}

/// The raw authentication results, kept for diagnosis. When an aligned
/// result is `fail` while the raw one passed, these name the domain that
/// actually authenticated — which is how a third-party sender that signs
/// with its own envelope domain is recognised.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthResults {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dkim: Vec<DkimAuth>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub spf: Vec<SpfAuth>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkimAuth {
    pub domain: String,
    pub result: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpfAuth {
    pub domain: String,
    pub result: String,
}

/// A reporter's note that it applied something other than the published
/// policy — local overrides, forwarding allowances, sampling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reason {
    pub r#type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Unwrap an attachment into the XML documents it carries.
///
/// Reporters disagree about packaging: some send `.xml.gz`, some `.zip`,
/// some the bare document. Sniffing the magic bytes rather than trusting a
/// filename means the same code path serves a file on disk and a MIME part
/// whose declared content type is wrong — which it frequently is.
pub fn extract(blob: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    if blob.starts_with(&[0x1f, 0x8b]) {
        return Ok(vec![inflate_gzip(blob)?]);
    }
    if blob.starts_with(b"PK\x03\x04") {
        return unzip(blob);
    }
    if blob.len() > MAX_UNCOMPRESSED {
        return Err(Error::TooLarge);
    }
    Ok(vec![blob.to_vec()])
}

fn inflate_gzip(blob: &[u8]) -> Result<Vec<u8>, Error> {
    use std::io::Read as _;
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(blob)
        // One byte over the cap is enough to know, and stops us allocating
        // the whole of a bomb to find out.
        .take(MAX_UNCOMPRESSED as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| Error::Archive(clipped(&e.to_string())))?;
    if out.len() > MAX_UNCOMPRESSED {
        return Err(Error::TooLarge);
    }
    Ok(out)
}

fn unzip(blob: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    use std::io::Read as _;
    let reader = std::io::Cursor::new(blob);
    let mut zip =
        zip::ZipArchive::new(reader).map_err(|e| Error::Archive(clipped(&e.to_string())))?;
    if zip.len() > MAX_ARCHIVE_MEMBERS {
        return Err(Error::TooManyMembers);
    }
    let mut out = Vec::new();
    for i in 0..zip.len() {
        let mut entry = zip
            .by_index(i)
            .map_err(|e| Error::Archive(clipped(&e.to_string())))?;
        if !entry.is_file() {
            continue;
        }
        // The declared size is a claim, so it is checked before allocating
        // AND the read itself is capped. Believing either one alone is how
        // a zip bomb gets in.
        if entry.size() > MAX_UNCOMPRESSED as u64 {
            return Err(Error::TooLarge);
        }
        let mut buf = Vec::new();
        (&mut entry)
            .take(MAX_UNCOMPRESSED as u64 + 1)
            .read_to_end(&mut buf)
            .map_err(|e| Error::Archive(clipped(&e.to_string())))?;
        if buf.len() > MAX_UNCOMPRESSED {
            return Err(Error::TooLarge);
        }
        out.push(buf);
    }
    if out.is_empty() {
        return Err(Error::Empty);
    }
    Ok(out)
}

/// Parse one aggregate report document.
pub fn parse(xml: &[u8]) -> Result<Report, Error> {
    // Lossy on purpose: a report with one bad byte in a comment field is
    // still a report, and refusing it loses a day of a receiver's history
    // over a character nobody reads.
    let text = String::from_utf8_lossy(xml);
    let text = text.trim_start_matches('\u{feff}').trim();

    // No DMARC report has a DOCTYPE. Anything that declares one is either
    // broken or trying something, and quick-xml should not be asked to
    // decide which.
    let head = text.get(..4096).unwrap_or(text).to_ascii_lowercase();
    if head.contains("<!doctype") || head.contains("<!entity") {
        return Err(Error::Doctype);
    }

    let feedback: raw::Feedback =
        quick_xml::de::from_str(text).map_err(|e| Error::Xml(clipped(&e.to_string())))?;

    let meta = feedback
        .report_metadata
        .ok_or(Error::NotAReport("no report_metadata"))?;
    let policy = feedback
        .policy_published
        .ok_or(Error::NotAReport("no policy_published"))?;
    let range = meta.date_range.unwrap_or_default();

    Ok(Report {
        org_name: trimmed(meta.org_name).unwrap_or_else(|| "unknown".into()),
        email: trimmed(meta.email),
        report_id: trimmed(meta.report_id).ok_or(Error::NotAReport("no report_id"))?,
        begin: number(range.begin).unwrap_or(0),
        end: number(range.end).unwrap_or(0),
        domain: trimmed(policy.domain)
            .map(|d| d.to_ascii_lowercase())
            .ok_or(Error::NotAReport("no policy domain"))?,
        p: trimmed(policy.p),
        sp: trimmed(policy.sp),
        pct: number(policy.pct).map(|n| n as i32),
        adkim: trimmed(policy.adkim),
        aspf: trimmed(policy.aspf),
        records: feedback.records.into_iter().map(record).collect(),
    })
}

fn record(rec: raw::Record) -> Record {
    let row = rec.row.unwrap_or_default();
    let evaluated = row.policy_evaluated.unwrap_or_default();
    let auth = rec.auth_results.unwrap_or_default();
    Record {
        source_ip: trimmed(row.source_ip).unwrap_or_default(),
        count: number(row.count).unwrap_or(0),
        // An absent verdict is reported as unknown rather than guessed at
        // in either direction.
        disposition: lowered(evaluated.disposition),
        dkim_aligned: lowered(evaluated.dkim),
        spf_aligned: lowered(evaluated.spf),
        header_from: rec
            .identifiers
            .unwrap_or_default()
            .header_from
            .and_then(trimmed_opt)
            .map(|h| h.to_ascii_lowercase())
            .unwrap_or_default(),
        auth: AuthResults {
            dkim: auth
                .dkim
                .into_iter()
                .map(|d| DkimAuth {
                    domain: trimmed(d.domain).unwrap_or_default().to_ascii_lowercase(),
                    result: lowered(d.result),
                    selector: trimmed(d.selector),
                })
                .collect(),
            spf: auth
                .spf
                .into_iter()
                .map(|s| SpfAuth {
                    domain: trimmed(s.domain).unwrap_or_default().to_ascii_lowercase(),
                    result: lowered(s.result),
                })
                .collect(),
        },
        reasons: evaluated
            .reason
            .into_iter()
            .map(|r| Reason {
                r#type: lowered(r.r#type),
                comment: trimmed(r.comment),
            })
            .collect(),
    }
}

/// Bound what a parser failure is allowed to say.
///
/// Deserialisers quote the input they choked on, so a file that is not a
/// report at all — a database, an image, anything that got into the
/// mailbox — turns one failure into megabytes of log. This runs unattended
/// against a mailbox anyone can write to, which makes an unbounded error
/// message a way to fill a disk. One clipped line on one line.
fn clipped(message: &str) -> String {
    const LIMIT: usize = 160;
    let flat: String = message
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let flat = flat.split_whitespace().collect::<Vec<_>>().join(" ");
    match flat.char_indices().nth(LIMIT) {
        Some((cut, _)) => format!("{}...", &flat[..cut]),
        None => flat,
    }
}

fn trimmed(value: Option<String>) -> Option<String> {
    value.and_then(trimmed_opt)
}

fn trimmed_opt(value: String) -> Option<String> {
    let value = value.trim().to_string();
    (!value.is_empty()).then_some(value)
}

fn lowered(value: Option<String>) -> String {
    trimmed(value)
        .map(|v| v.to_ascii_lowercase())
        .unwrap_or_else(|| "unknown".into())
}

/// Numbers arrive as text and reporters pad them. A value we cannot read
/// is absent rather than zero-by-accident.
fn number(value: Option<String>) -> Option<i64> {
    trimmed(value)?.parse().ok()
}

/// The wire shapes, kept private. Every field is optional because the
/// schema is advisory in practice: reporters omit `sp`, omit `pct`, and
/// occasionally omit things RFC 7489 calls required. A report that is
/// mostly there is worth more than a parse error.
mod raw {
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    pub struct Feedback {
        pub report_metadata: Option<ReportMetadata>,
        pub policy_published: Option<PolicyPublished>,
        #[serde(default, rename = "record")]
        pub records: Vec<Record>,
    }

    #[derive(Debug, Deserialize)]
    pub struct ReportMetadata {
        pub org_name: Option<String>,
        pub email: Option<String>,
        pub report_id: Option<String>,
        pub date_range: Option<DateRange>,
    }

    #[derive(Debug, Default, Deserialize)]
    pub struct DateRange {
        pub begin: Option<String>,
        pub end: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    pub struct PolicyPublished {
        pub domain: Option<String>,
        pub adkim: Option<String>,
        pub aspf: Option<String>,
        pub p: Option<String>,
        pub sp: Option<String>,
        pub pct: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    pub struct Record {
        pub row: Option<Row>,
        pub identifiers: Option<Identifiers>,
        pub auth_results: Option<AuthResults>,
    }

    #[derive(Debug, Default, Deserialize)]
    pub struct Row {
        pub source_ip: Option<String>,
        pub count: Option<String>,
        pub policy_evaluated: Option<PolicyEvaluated>,
    }

    #[derive(Debug, Default, Deserialize)]
    pub struct PolicyEvaluated {
        pub disposition: Option<String>,
        pub dkim: Option<String>,
        pub spf: Option<String>,
        #[serde(default)]
        pub reason: Vec<Reason>,
    }

    #[derive(Debug, Deserialize)]
    pub struct Reason {
        pub r#type: Option<String>,
        pub comment: Option<String>,
    }

    #[derive(Debug, Default, Deserialize)]
    pub struct Identifiers {
        pub header_from: Option<String>,
    }

    #[derive(Debug, Default, Deserialize)]
    pub struct AuthResults {
        #[serde(default)]
        pub dkim: Vec<DkimAuth>,
        #[serde(default)]
        pub spf: Vec<SpfAuth>,
    }

    #[derive(Debug, Deserialize)]
    pub struct DkimAuth {
        pub domain: Option<String>,
        pub result: Option<String>,
        pub selector: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    pub struct SpfAuth {
        pub domain: Option<String>,
        pub result: Option<String>,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A complete report in the shape reporters actually send.
    const REPORT: &str = r#"<?xml version="1.0" ?>
<feedback>
  <version>1.0</version>
  <report_metadata>
    <org_name>reporter.example</org_name>
    <email>noreply-dmarc@reporter.example</email>
    <report_id>20260819.abc123@reporter.example</report_id>
    <date_range><begin>1787011200</begin><end>1787097599</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>mail.example.com</domain>
    <adkim>r</adkim><aspf>r</aspf><p>quarantine</p><sp>quarantine</sp><pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>198.51.100.7</source_ip>
      <count>31</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>Mail.Example.COM</header_from></identifiers>
    <auth_results>
      <dkim><domain>mail.example.com</domain><result>pass</result><selector>sel2026</selector></dkim>
      <spf><domain>mail.example.com</domain><result>pass</result></spf>
    </auth_results>
  </record>
</feedback>"#;

    #[test]
    fn a_report_parses_whole() {
        let r = parse(REPORT.as_bytes()).expect("parses");
        assert_eq!(r.org_name, "reporter.example");
        assert_eq!(r.report_id, "20260819.abc123@reporter.example");
        assert_eq!(r.domain, "mail.example.com");
        assert_eq!(r.p.as_deref(), Some("quarantine"));
        assert_eq!(r.pct, Some(100));
        assert_eq!(r.begin, 1787011200);
        assert_eq!(r.records.len(), 1);

        let rec = &r.records[0];
        assert_eq!(rec.source_ip, "198.51.100.7");
        assert_eq!(rec.count, 31);
        assert!(rec.passed());
        // Case folded, because reporters disagree about it and a domain
        // is a domain.
        assert_eq!(rec.header_from, "mail.example.com");
        assert_eq!(rec.auth.dkim[0].selector.as_deref(), Some("sel2026"));
    }

    /// The case that makes the raw results worth storing at all.
    ///
    /// A third-party sender signing with its own envelope domain passes
    /// SPF for THAT domain while failing DMARC alignment for the one in
    /// the header. Reading only `policy_evaluated` says "spf fail" and
    /// leaves an operator hunting a broken SPF record that is fine; the
    /// authenticated domain is the whole diagnosis.
    #[test]
    fn an_unaligned_source_keeps_the_domain_that_authenticated() {
        let xml = r#"<feedback>
  <report_metadata><org_name>reporter.example</org_name><report_id>r2</report_id>
    <date_range><begin>1</begin><end>2</end></date_range></report_metadata>
  <policy_published><domain>example.com</domain><p>none</p></policy_published>
  <record>
    <row><source_ip>203.0.113.9</source_ip><count>2</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results>
      <dkim><domain>example.com</domain><result>pass</result><selector>third</selector></dkim>
      <spf><domain>bounces.sender.example</domain><result>pass</result></spf>
    </auth_results>
  </record>
</feedback>"#;
        let r = parse(xml.as_bytes()).expect("parses");
        let rec = &r.records[0];
        assert_eq!(rec.spf_aligned, "fail");
        // DMARC still passes: one aligned mechanism is enough.
        assert!(rec.passed());
        assert_eq!(rec.auth.spf[0].domain, "bounces.sender.example");
        assert_eq!(rec.auth.spf[0].result, "pass");
    }

    /// `sp` and `pct` are routinely omitted, and a missing optional field
    /// must not cost the whole report.
    #[test]
    fn a_sparse_report_still_parses() {
        let xml = r#"<feedback>
  <report_metadata><org_name>r</org_name><report_id>x</report_id></report_metadata>
  <policy_published><domain>example.com</domain></policy_published>
</feedback>"#;
        let r = parse(xml.as_bytes()).expect("parses");
        assert_eq!(r.domain, "example.com");
        assert_eq!(r.sp, None);
        assert_eq!(r.pct, None);
        assert_eq!(r.begin, 0);
        assert!(r.records.is_empty());
    }

    /// An override tells you the reporter did not apply the published
    /// policy — without it, a forwarded message looks like a policy that
    /// is not working.
    #[test]
    fn policy_overrides_are_kept() {
        let xml = r#"<feedback>
  <report_metadata><org_name>r</org_name><report_id>x</report_id></report_metadata>
  <policy_published><domain>example.com</domain><p>reject</p></policy_published>
  <record>
    <row><source_ip>203.0.113.1</source_ip><count>1</count>
      <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf>
        <reason><type>forwarded</type><comment>known forwarder</comment></reason>
      </policy_evaluated></row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results/>
  </record>
</feedback>"#;
        let r = parse(xml.as_bytes()).expect("parses");
        let rec = &r.records[0];
        assert!(!rec.passed());
        assert_eq!(rec.reasons[0].r#type, "forwarded");
        assert_eq!(rec.reasons[0].comment.as_deref(), Some("known forwarder"));
    }

    #[test]
    fn several_records_all_survive() {
        let xml = REPORT.replace(
            "</record>",
            r#"</record>
  <record>
    <row><source_ip>203.0.113.2</source_ip><count>4</count>
      <policy_evaluated><disposition>quarantine</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>mail.example.com</header_from></identifiers>
    <auth_results/>
  </record>"#,
        );
        let r = parse(xml.as_bytes()).expect("parses");
        assert_eq!(r.records.len(), 2);
        assert_eq!(r.records[1].disposition, "quarantine");
        assert!(!r.records[1].passed());
    }

    #[test]
    fn a_gzipped_report_is_unwrapped() {
        use std::io::Write as _;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(REPORT.as_bytes()).unwrap();
        let blob = enc.finish().unwrap();

        let docs = extract(&blob).expect("unwraps");
        assert_eq!(docs.len(), 1);
        assert_eq!(parse(&docs[0]).unwrap().domain, "mail.example.com");
    }

    #[test]
    fn a_zipped_report_is_unwrapped() {
        use std::io::Write as _;
        let mut zw = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        zw.start_file("report.xml", zip::write::SimpleFileOptions::default())
            .unwrap();
        zw.write_all(REPORT.as_bytes()).unwrap();
        let blob = zw.finish().unwrap().into_inner();

        let docs = extract(&blob).expect("unwraps");
        assert_eq!(docs.len(), 1);
        assert_eq!(parse(&docs[0]).unwrap().domain, "mail.example.com");
    }

    /// A bare document is a document. Reporters send all three packagings
    /// and the content type on the MIME part cannot be trusted to say
    /// which.
    #[test]
    fn a_bare_document_needs_no_unwrapping() {
        let docs = extract(REPORT.as_bytes()).expect("passes through");
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0], REPORT.as_bytes());
    }

    /// The mailbox this reads from is open to the internet, so the parser
    /// is a place an attacker can reach.
    #[test]
    fn a_document_declaring_entities_is_refused() {
        let xml = "<?xml version=\"1.0\"?>\n\
                   <!DOCTYPE feedback [<!ENTITY boom \"AAAAAAAA\">]>\n\
                   <feedback>&boom;</feedback>";
        assert!(matches!(parse(xml.as_bytes()), Err(Error::Doctype)));
    }

    /// The mailbox receives whatever anyone sends it, and a deserialiser
    /// quotes what it choked on. Without a bound, one file that is not a
    /// report writes megabytes to the log.
    #[test]
    fn a_failure_message_cannot_run_away() {
        let junk = format!("<feedback>{}</feedback>", "A".repeat(500_000));
        let err = parse(junk.as_bytes()).expect_err("not a report");
        let text = err.to_string();
        assert!(text.len() < 400, "error was {} bytes", text.len());
        assert!(!text.contains('\n'), "error must stay on one line");
    }

    #[test]
    fn a_decompression_bomb_is_refused() {
        use std::io::Write as _;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        // Compresses to a few kilobytes, expands past the cap.
        let chunk = vec![b'A'; 1024 * 1024];
        for _ in 0..(MAX_UNCOMPRESSED / chunk.len() + 1) {
            enc.write_all(&chunk).unwrap();
        }
        let blob = enc.finish().unwrap();
        assert!(blob.len() < 1024 * 1024, "bomb should be small on the wire");
        assert!(matches!(extract(&blob), Err(Error::TooLarge)));
    }

    #[test]
    fn something_that_is_not_a_report_is_rejected_not_half_parsed() {
        let xml = "<feedback><report_metadata><org_name>r</org_name></report_metadata>\
                   <policy_published><domain>example.com</domain></policy_published></feedback>";
        assert!(matches!(parse(xml.as_bytes()), Err(Error::NotAReport(_))));
        assert!(parse(b"<html><body>hello</body></html>").is_err());
    }
}
