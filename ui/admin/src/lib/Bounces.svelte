<script>
  import { api, fmtTime } from "./api.svelte.js";

  let rows = $state(null);
  let error = $state("");
  let raw = $state(null); // { id, text }

  // Keyset paging: stack of cursors (null = first page) + position.
  let stack = $state([null]);
  let pos = $state(0);
  let next = $state(null);

  async function load() {
    error = "";
    try {
      const params = new URLSearchParams();
      const cursor = stack[pos];
      if (cursor) params.set("before_id", cursor.before_id);
      const page = await api(`/bounces?${params}`);
      rows = page.items;
      next = page.next;
    } catch (e) {
      error = e.message;
    }
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

  async function showRaw(id) {
    error = "";
    try {
      raw = { id, text: await api(`/bounces/${id}/raw`) };
    } catch (e) {
      error = e.message;
    }
  }

  $effect(() => {
    load();
  });
</script>

<div class="card bg-base-100 border border-base-300">
  <div class="card-body gap-3">
    <h2 class="card-title text-base">Bounce reports</h2>
    <p class="text-sm opacity-70">
      Raw DSNs as Postfix piped them in, parsed or not. An unparsed bounce
      (no classification) is a parser bug report — the evidence is kept so
      it can be fixed.
    </p>

    {#if error}<div class="alert alert-error text-sm py-2">{error}</div>{/if}

    {#if raw}
      <div class="flex items-center justify-between">
        <h3 class="font-semibold text-sm">Raw DSN #{raw.id}</h3>
        <button class="btn btn-xs" onclick={() => (raw = null)}>Close</button>
      </div>
      <pre class="bg-base-200 rounded p-3 text-xs whitespace-pre-wrap max-h-96 overflow-y-auto">{raw.text}</pre>
    {/if}

    {#if !rows}
      <span class="loading loading-spinner"></span>
    {:else}
      <div class="overflow-x-auto">
        <table class="table table-sm">
          <thead>
            <tr>
              <th>Received</th>
              <th>Recipient</th>
              <th class="hidden sm:table-cell">Status</th>
              <th>Class</th>
              <th class="hidden sm:table-cell">Matched</th>
              <th class="hidden md:table-cell">Diagnostic</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {#each rows as b (b.id)}
              <tr>
                <td class="whitespace-nowrap">{fmtTime(b.received_at)}</td>
                <td class="break-all">{b.final_rcpt ?? "–"}</td>
                <td class="hidden sm:table-cell">{b.status_code ?? "–"}</td>
                <td>
                  {#if b.classification === "permanent"}
                    <span class="badge badge-sm badge-error">permanent</span>
                  {:else if b.classification === "transient"}
                    <span class="badge badge-sm badge-warning">transient</span>
                  {:else}
                    <span class="badge badge-sm badge-neutral">{b.classification ?? "unparsed"}</span>
                  {/if}
                </td>
                <td class="hidden sm:table-cell">
                  {#if b.message_id}
                    <span class="badge badge-sm badge-success">yes</span>
                  {:else}
                    <span class="badge badge-sm badge-warning">no</span>
                  {/if}
                </td>
                <td class="hidden md:table-cell max-w-md truncate" title={b.diagnostic}>{b.diagnostic ?? "–"}</td>
                <td><button class="btn btn-xs" onclick={() => showRaw(b.id)}>Raw</button></td>
              </tr>
            {:else}
              <tr><td colspan="7" class="opacity-60">No bounces recorded. Good.</td></tr>
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
