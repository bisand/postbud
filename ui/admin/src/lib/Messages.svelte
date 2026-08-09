<script>
  import { api, fmtTime } from "./api.svelte.js";

  // `param` is the optional message id from the route (#messages/{id}).
  // The detail view lives in the URL so the browser's Back button returns
  // to the list — with its filters and page intact, because this
  // component never unmounts while the section stays "messages".
  let { param = null } = $props();

  let rows = $state(null);
  let error = $state("");
  let detail = $state(null);

  let status = $state("");
  let rcpt = $state("");
  let tenant = $state("");

  // Keyset paging: a stack of page cursors (null = first page) and the
  // position we are at. "Older" pushes the server's `next` cursor,
  // "Newer" steps back. A new search resets the stack.
  let stack = $state([null]);
  let pos = $state(0);
  let next = $state(null);

  const badge = {
    sent: "badge-success",
    failed: "badge-error",
    queued: "badge-warning",
    suppressed: "badge-neutral",
  };

  async function load() {
    error = "";
    rows = null;
    try {
      const params = new URLSearchParams();
      if (status) params.set("status", status);
      if (rcpt) params.set("rcpt", rcpt);
      if (tenant) params.set("tenant", tenant);
      const cursor = stack[pos];
      if (cursor) {
        params.set("before", cursor.before);
        params.set("before_id", cursor.before_id);
      }
      const page = await api(`/messages?${params}`);
      rows = page.items;
      next = page.next;
    } catch (e) {
      error = e.message;
    }
  }

  function search(event) {
    event.preventDefault();
    stack = [null];
    pos = 0;
    load();
  }

  function older() {
    if (!next) return;
    if (pos === stack.length - 1) stack = [...stack, next];
    pos += 1;
    load();
  }

  function newer() {
    if (pos === 0) return;
    pos -= 1;
    load();
  }

  $effect(() => {
    load();
  });

  // The route decides whether the detail view is open.
  $effect(() => {
    if (param) {
      detail = null;
      api(`/messages/${param}`)
        .then((d) => (detail = d))
        .catch((e) => (error = e.message));
    } else {
      detail = null;
    }
  });
</script>

{#if param}
  {#if detail}
    <div class="card bg-base-100 border border-base-300">
      <div class="card-body gap-3">
        <div class="flex items-start justify-between gap-2">
          <div>
            <h2 class="card-title text-base break-all">{detail.subject}</h2>
            <p class="text-sm opacity-70">
              {detail.tenant} → {detail.rcpt_to}
              <span class="badge badge-sm ml-2 {badge[detail.status] ?? ''}">{detail.status}</span>
            </p>
          </div>
          <a class="btn btn-sm" href="#messages">← Back</a>
        </div>

        <div class="grid sm:grid-cols-2 gap-x-8 gap-y-1 text-sm">
          <div><span class="opacity-60">From:</span> {detail.from_name ? `${detail.from_name} <${detail.mail_from}>` : detail.mail_from}</div>
          <div><span class="opacity-60">Reply-to:</span> {detail.reply_to ?? "–"}</div>
          <div><span class="opacity-60">Created:</span> {fmtTime(detail.created_at)}</div>
          <div><span class="opacity-60">Completed:</span> {fmtTime(detail.completed_at)}</div>
          <div class="break-all"><span class="opacity-60">Idempotency key:</span> <code class="text-xs">{detail.idempotency_key}</code></div>
          <div class="break-all"><span class="opacity-60">Postfix queue id:</span> <code class="text-xs">{detail.relay_queue_id ?? "–"}</code></div>
        </div>

        {#if detail.last_error}
          <div class="alert alert-error text-sm py-2">{detail.last_error}</div>
        {/if}

        <h3 class="font-semibold text-sm mt-2">Delivery attempts</h3>
        <div class="overflow-x-auto">
          <table class="table table-sm">
            <thead>
              <tr><th>#</th><th>Outcome</th><th>SMTP</th><th>Queue id</th><th>Detail</th><th>When</th></tr>
            </thead>
            <tbody>
              {#each detail.delivery_attempts as a (a.attempt + a.finished_at)}
                <tr>
                  <td>{a.attempt}</td>
                  <td>{a.outcome}</td>
                  <td>{a.smtp_code ?? "–"}</td>
                  <td><code class="text-xs">{a.relay_queue_id ?? "–"}</code></td>
                  <td class="max-w-xs truncate" title={a.detail}>{a.detail ?? "–"}</td>
                  <td class="whitespace-nowrap">{fmtTime(a.finished_at)}</td>
                </tr>
              {:else}
                <tr><td colspan="6" class="opacity-60">No attempts yet.</td></tr>
              {/each}
            </tbody>
          </table>
        </div>

        {#if detail.bounces.length > 0}
          <h3 class="font-semibold text-sm mt-2">Bounces</h3>
          <div class="overflow-x-auto">
            <table class="table table-sm">
              <thead>
                <tr><th>Received</th><th>Status</th><th>Class</th><th>Diagnostic</th></tr>
              </thead>
              <tbody>
                {#each detail.bounces as b (b.id)}
                  <tr>
                    <td class="whitespace-nowrap">{fmtTime(b.received_at)}</td>
                    <td>{b.status_code ?? "–"}</td>
                    <td>{b.classification ?? "–"}</td>
                    <td class="max-w-md truncate" title={b.diagnostic}>{b.diagnostic ?? "–"}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        {/if}

        <h3 class="font-semibold text-sm mt-2">Content</h3>
        {#if detail.body_purged_at}
          <p class="text-sm opacity-70">
            Body purged {fmtTime(detail.body_purged_at)} (retention policy —
            the delivery record above is kept).
          </p>
        {:else if detail.body_text}
          <pre class="bg-base-200 rounded p-3 text-xs whitespace-pre-wrap max-h-64 overflow-y-auto">{detail.body_text}</pre>
          {#if detail.has_html}<p class="text-xs opacity-60">An HTML alternative exists; the text part is shown.</p>{/if}
        {:else if detail.has_html}
          <p class="text-sm opacity-70">HTML-only message (no text part).</p>
        {:else}
          <p class="text-sm opacity-70">No body stored.</p>
        {/if}

        {#if detail.attachments.length > 0}
          <h3 class="font-semibold text-sm mt-2">Attachments</h3>
          <ul class="text-sm list-disc list-inside">
            {#each detail.attachments as a (a.sha256)}
              <li>
                {a.filename} <span class="opacity-60">({a.content_type}, {a.size} bytes)</span>
                <code class="text-xs opacity-60 break-all">sha256:{a.sha256}</code>
              </li>
            {/each}
          </ul>
        {/if}
      </div>
    </div>
  {:else if error}
    <div class="alert alert-error text-sm py-2">
      {error} <a class="link" href="#messages">Back to the list</a>
    </div>
  {:else}
    <span class="loading loading-spinner"></span>
  {/if}
{:else}
  <div class="card bg-base-100 border border-base-300">
    <div class="card-body gap-3">
      <h2 class="card-title text-base">Messages</h2>
      <form class="flex flex-wrap gap-2 items-end" onsubmit={search}>
        <label class="form-control">
          <span class="label-text text-xs mb-1">Recipient contains</span>
          <input class="input input-bordered input-sm" bind:value={rcpt} placeholder="name@example.com" />
        </label>
        <label class="form-control">
          <span class="label-text text-xs mb-1">Status</span>
          <select class="select select-bordered select-sm" bind:value={status}>
            <option value="">all</option>
            <option>queued</option>
            <option>sent</option>
            <option>failed</option>
            <option>suppressed</option>
          </select>
        </label>
        <label class="form-control">
          <span class="label-text text-xs mb-1">Tenant</span>
          <input class="input input-bordered input-sm" bind:value={tenant} placeholder="exact name" />
        </label>
        <button class="btn btn-sm btn-primary">Search</button>
      </form>

      {#if error}
        <div class="alert alert-error text-sm py-2">{error}</div>
      {:else if !rows}
        <span class="loading loading-spinner"></span>
      {:else}
        <div class="overflow-x-auto">
          <table class="table table-sm">
            <thead>
              <tr>
                <th>Created</th>
                <th class="hidden sm:table-cell">Tenant</th>
                <th>Recipient</th>
                <th class="hidden md:table-cell">Subject</th>
                <th>Status</th>
                <th class="hidden sm:table-cell">Att.</th>
              </tr>
            </thead>
            <tbody>
              {#each rows as m (m.id)}
                <tr
                  class="hover cursor-pointer"
                  onclick={() => (location.hash = `#messages/${m.id}`)}
                >
                  <td class="whitespace-nowrap">{fmtTime(m.created_at)}</td>
                  <td class="hidden sm:table-cell">{m.tenant}</td>
                  <td class="break-all">{m.rcpt_to}</td>
                  <td class="hidden md:table-cell max-w-xs truncate" title={m.subject}>{m.subject}</td>
                  <td><span class="badge badge-sm {badge[m.status] ?? ''}">{m.status}</span></td>
                  <td class="hidden sm:table-cell">{m.attempts}</td>
                </tr>
              {:else}
                <tr><td colspan="6" class="opacity-60">Nothing matched.</td></tr>
              {/each}
            </tbody>
          </table>
        </div>
        <div class="flex items-center gap-2">
          <button class="btn btn-sm" disabled={pos === 0} onclick={newer}>← Newer</button>
          <button class="btn btn-sm" disabled={!next} onclick={older}>Older →</button>
          {#if pos > 0}<span class="text-xs opacity-60">page {pos + 1}</span>{/if}
        </div>
      {/if}
    </div>
  </div>
{/if}
