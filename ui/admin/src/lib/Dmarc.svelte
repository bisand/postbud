<script>
  import { api, fmtTime } from "./api.svelte.js";

  // `param` is the optional domain from the route (#dmarc/{domain}), so
  // the browser's Back button leaves the detail rather than the app.
  let { param = null } = $props();

  let rows = $state(null);
  let detail = $state(null);
  let error = $state("");
  let days = $state(30);

  const selected = $derived(param);

  async function loadList() {
    error = "";
    try {
      rows = await api("/dmarc");
    } catch (e) {
      error = e.message;
    }
  }

  async function loadDetail(domain, window) {
    error = "";
    detail = null;
    try {
      detail = await api(`/dmarc/${encodeURIComponent(domain)}?days=${window}`);
    } catch (e) {
      error = e.message;
    }
  }

  $effect(() => {
    loadList();
  });

  $effect(() => {
    if (selected) loadDetail(selected, days);
    else detail = null;
  });

  const pct = (passed, total) => (total > 0 ? (100 * passed) / total : 0);

  function rateClass(rate, total) {
    if (total === 0) return "opacity-50";
    if (rate >= 99.95) return "text-success";
    if (rate >= 95) return "text-warning";
    return "text-error";
  }

  // The published policy as a receiver saw it. Enforcement is the whole
  // point of DMARC, so p=none reads as unfinished rather than neutral.
  const policyClass = { reject: "badge-success", quarantine: "badge-info", none: "badge-ghost" };

  // Which mechanism actually carried DMARC for this domain. A domain
  // riding one alone is a single rotation away from failing entirely, and
  // a pass rate of 100% says nothing about it.
  const legs = $derived.by(() => {
    if (!detail?.sources?.length) return null;
    const t = detail.sources.reduce(
      (a, s) => ({
        messages: a.messages + s.messages,
        dkim: a.dkim + s.dkim_passed,
        spf: a.spf + s.spf_passed,
      }),
      { messages: 0, dkim: 0, spf: 0 },
    );
    if (t.messages === 0) return null;
    if (t.spf === 0) return { alone: "DKIM", missing: "SPF" };
    if (t.dkim === 0) return { alone: "SPF", missing: "DKIM" };
    return null;
  });

  // Named so a failing mechanism points at the domain that DID
  // authenticate. "spf: fail" on its own sends an operator hunting a
  // broken SPF record that is perfectly fine — the envelope simply
  // belonged to a third-party sender.
  function unaligned(source) {
    const notes = [];
    if (source.spf_passed === 0 && source.auth?.spf?.length) {
      notes.push(`SPF authenticated ${source.auth.spf.map((s) => `${s.domain} (${s.result})`).join(", ")} — not the header domain`);
    }
    if (source.dkim_passed === 0 && source.auth?.dkim?.length) {
      notes.push(`DKIM authenticated ${source.auth.dkim.map((d) => `${d.domain} (${d.result})`).join(", ")} — not the header domain`);
    }
    return notes;
  }

  function selector(source) {
    return source.auth?.dkim?.find((d) => d.selector)?.selector ?? null;
  }
</script>

<div class="flex flex-col gap-4">
  {#if error}<div class="alert alert-error text-sm py-2">{error}</div>{/if}

  {#if !selected}
    <div class="card bg-base-100 border border-base-300">
      <div class="card-body gap-2">
        <h2 class="card-title text-base">What the receivers concluded</h2>
        <p class="text-xs opacity-60">
          Aggregate reports are the only place a receiver tells you what it decided
          about your mail. Nothing else here can: a message the far end quarantined
          was still a clean handoff to the relay, so it counts as delivered and
          never produces a bounce.
        </p>
        <p class="text-xs opacity-60">
          Each row is a claim by whoever sent the report, not a fact — the address
          in a <span class="font-mono">rua=</span> tag is public and anyone may post
          to it. Nothing on this page changes suppression or domain status.
        </p>
      </div>
    </div>

    {#if !rows}
      <span class="loading loading-spinner"></span>
    {:else if rows.length === 0}
      <div class="card bg-base-100 border border-base-300">
        <div class="card-body">
          <p class="text-sm opacity-70">
            No reports yet. The worker reads the mailbox hourly when
            <span class="font-mono">DMARC_EMAIL_IMAP</span> is configured; existing
            files can be loaded with <span class="font-mono">postbud dmarc-import</span>.
          </p>
        </div>
      </div>
    {:else}
      <div class="overflow-x-auto">
        <table class="table table-sm">
          <thead>
            <tr>
              <th>Domain</th>
              <th>Policy</th>
              <th class="text-right">Messages</th>
              <th class="text-right">DMARC pass</th>
              <th>Seen</th>
            </tr>
          </thead>
          <tbody>
            {#each rows as d (d.domain)}
              {@const rate = pct(d.passed, d.messages)}
              <tr class="hover">
                <td>
                  <a class="link link-hover font-mono" href="#dmarc/{d.domain}">{d.domain}</a>
                  <div class="text-xs opacity-50">
                    {d.reports} report{d.reports === 1 ? "" : "s"} from
                    {d.reporters} reporter{d.reporters === 1 ? "" : "s"}
                  </div>
                </td>
                <td>
                  <span class="badge badge-sm {policyClass[d.policy] ?? 'badge-ghost'}">
                    p={d.policy ?? "?"}
                  </span>
                </td>
                <td class="text-right tabular-nums">{d.messages}</td>
                <td class="text-right tabular-nums font-semibold {rateClass(rate, d.messages)}">
                  {rate.toFixed(1)}%
                </td>
                <td class="text-xs opacity-60 whitespace-nowrap">
                  {fmtTime(d.first_seen)} – {fmtTime(d.last_seen)}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      <p class="text-xs opacity-60">
        One reporter is one receiver's opinion. A domain seen by a single reporter
        over a single day is not yet evidence that its mail authenticates
        everywhere.
      </p>
    {/if}
  {:else}
    <div class="flex items-center gap-3 flex-wrap">
      <a class="btn btn-sm" href="#dmarc">← All domains</a>
      <span class="font-mono text-lg">{selected}</span>
      <div class="join ml-auto">
        {#each [7, 30, 90] as option}
          <button
            class="btn btn-sm join-item {days === option ? 'btn-active' : ''}"
            onclick={() => (days = option)}
          >
            {option}d
          </button>
        {/each}
      </div>
    </div>

    {#if !detail}
      <span class="loading loading-spinner"></span>
    {:else if detail.sources.length === 0}
      <div class="alert text-sm py-2">Nothing reported for this domain in the last {days} days.</div>
    {:else}
      {#if legs}
        <div class="alert alert-warning text-sm py-2">
          <span>
            Every message here passes on <strong>{legs.alone} alone</strong> — no message
            aligned {legs.missing}. DMARC still passes, but one signing change would take
            all of it down at once. A pass rate of 100% does not show this.
          </span>
        </div>
      {/if}

      <div class="overflow-x-auto">
        <table class="table table-sm">
          <thead>
            <tr>
              <th>Source</th>
              <th class="text-right">Messages</th>
              <th class="text-right">Pass</th>
              <th>DKIM</th>
              <th>SPF</th>
              <th>Disposition</th>
            </tr>
          </thead>
          <tbody>
            {#each detail.sources as s (s.source_ip)}
              {@const rate = pct(s.passed, s.messages)}
              {@const notes = unaligned(s)}
              <tr>
                <td class="align-top">
                  <span class="font-mono text-sm">{s.source_ip}</span>
                  {#if selector(s)}
                    <div class="text-xs opacity-50">selector {selector(s)}</div>
                  {/if}
                </td>
                <td class="align-top text-right tabular-nums">{s.messages}</td>
                <td class="align-top text-right tabular-nums font-semibold {rateClass(rate, s.messages)}">
                  {rate.toFixed(1)}%
                </td>
                <td class="align-top">
                  <span class="badge badge-sm {s.dkim_passed > 0 ? 'badge-success' : 'badge-ghost'}">
                    {s.dkim_passed === s.messages ? "aligned" : s.dkim_passed === 0 ? "no" : "partial"}
                  </span>
                </td>
                <td class="align-top">
                  <span class="badge badge-sm {s.spf_passed > 0 ? 'badge-success' : 'badge-ghost'}">
                    {s.spf_passed === s.messages ? "aligned" : s.spf_passed === 0 ? "no" : "partial"}
                  </span>
                </td>
                <td class="align-top">
                  <div class="text-xs opacity-70">{s.dispositions.join(", ")}</div>
                  {#each notes as note}
                    <div class="text-xs opacity-50">{note}</div>
                  {/each}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>

      <div class="card bg-base-100 border border-base-300">
        <div class="card-body gap-2">
          <h2 class="card-title text-base">By day</h2>
          <p class="text-xs opacity-60">
            A single day says very little; the series is the point. A gap is a day
            no reporter sent anything, not a day nothing was delivered.
          </p>
          <div class="overflow-x-auto">
            <table class="table table-xs">
              <tbody>
                {#each detail.daily as point (point.day)}
                  {@const rate = pct(point.passed, point.messages)}
                  <tr>
                    <td class="font-mono whitespace-nowrap">{point.day}</td>
                    <td class="w-full">
                      <progress
                        class="progress {rate >= 99.95 ? 'progress-success' : 'progress-warning'} w-full"
                        value={point.passed}
                        max={point.messages}
                      ></progress>
                    </td>
                    <td class="text-right tabular-nums whitespace-nowrap">{point.messages}</td>
                    <td class="text-right tabular-nums {rateClass(rate, point.messages)}">
                      {rate.toFixed(1)}%
                    </td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    {/if}
  {/if}
</div>
