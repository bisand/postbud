<script>
  import { api, fmtTime } from "./api.svelte.js";

  let rows = $state(null);
  let tenants = $state([]);
  let error = $state("");
  let notice = $state("");

  let filter = $state("");
  let includeRemoved = $state(false);

  // Keyset paging: stack of cursors (null = first page) + position.
  let stack = $state([null]);
  let pos = $state(0);
  let next = $state(null);

  // Block form.
  let address = $state("");
  let scope = $state("");
  let detail = $state("");

  // Two-step confirm for lifting: never window.confirm.
  let confirmLift = $state(null);

  async function load() {
    error = "";
    rows = null;
    try {
      const params = new URLSearchParams();
      if (filter) params.set("address", filter);
      if (includeRemoved) params.set("include_removed", "true");
      const cursor = stack[pos];
      if (cursor) params.set("before_id", cursor.before_id);
      const page = await api(`/suppressions?${params}`);
      rows = page.items;
      next = page.next;
    } catch (e) {
      error = e.message;
    }
  }

  function research() {
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

  async function block(event) {
    event.preventDefault();
    error = "";
    notice = "";
    try {
      await api("/suppressions", {
        method: "POST",
        body: JSON.stringify({
          address,
          tenant_id: scope || null,
          detail: detail || null,
        }),
      });
      notice = `${address} blocked ${scope ? "for one tenant" : "globally"}.`;
      address = "";
      detail = "";
      await load();
    } catch (e) {
      error = e.message;
    }
  }

  async function lift(id) {
    error = "";
    notice = "";
    try {
      await api(`/suppressions/${id}`, { method: "DELETE" });
      notice = "Suppression lifted — the address can receive mail again.";
      confirmLift = null;
      await load();
    } catch (e) {
      error = e.message;
    }
  }

  $effect(() => {
    load();
    api("/tenants").then((t) => (tenants = t)).catch(() => {});
  });
</script>

<div class="flex flex-col gap-4">
  <div class="card bg-base-100 border border-base-300">
    <div class="card-body gap-3">
      <h2 class="card-title text-base">Block an address</h2>
      <p class="text-sm opacity-70">
        A blocked address is still recorded when a tenant tries to mail it —
        status <code>suppressed</code> — so "we deliberately did not send
        this" stays visible. Bounce-driven blocks are created automatically;
        this form is for manual ones.
      </p>
      <form class="flex flex-wrap gap-2 items-end" onsubmit={block}>
        <label class="form-control">
          <span class="label-text text-xs mb-1">Address</span>
          <input class="input input-bordered input-sm" bind:value={address} required placeholder="name@example.com" />
        </label>
        <label class="form-control">
          <span class="label-text text-xs mb-1">Scope</span>
          <select class="select select-bordered select-sm" bind:value={scope}>
            <option value="">global (all tenants)</option>
            {#each tenants as t (t.id)}
              <option value={t.id}>{t.name} only</option>
            {/each}
          </select>
        </label>
        <label class="form-control">
          <span class="label-text text-xs mb-1">Why (kept forever)</span>
          <input class="input input-bordered input-sm" bind:value={detail} placeholder="reason" />
        </label>
        <button class="btn btn-sm btn-primary">Block</button>
      </form>
      {#if notice}<div class="alert alert-success text-sm py-2">{notice}</div>{/if}
      {#if error}<div class="alert alert-error text-sm py-2">{error}</div>{/if}
    </div>
  </div>

  <div class="card bg-base-100 border border-base-300">
    <div class="card-body gap-3">
      <h2 class="card-title text-base">Suppression list</h2>
      <form
        class="flex flex-wrap gap-2 items-end"
        onsubmit={(e) => {
          e.preventDefault();
          research();
        }}
      >
        <label class="form-control">
          <span class="label-text text-xs mb-1">Address contains</span>
          <input class="input input-bordered input-sm" bind:value={filter} />
        </label>
        <label class="label cursor-pointer gap-2">
          <input type="checkbox" class="checkbox checkbox-sm" bind:checked={includeRemoved} />
          <span class="label-text text-xs">Include lifted (history)</span>
        </label>
        <button class="btn btn-sm">Search</button>
      </form>

      {#if !rows}
        <span class="loading loading-spinner"></span>
      {:else}
        <div class="overflow-x-auto">
          <table class="table table-sm">
            <thead>
              <tr><th>Address</th><th>Scope</th><th>Reason</th><th>Source</th><th>Created</th><th>Lifted</th><th></th></tr>
            </thead>
            <tbody>
              {#each rows as s (s.id)}
                <tr class={s.removed_at ? "opacity-50" : ""}>
                  <td class="break-all">{s.address}</td>
                  <td>{s.tenant ?? "global"}</td>
                  <td title={s.detail}>{s.reason}</td>
                  <td>{s.source}</td>
                  <td class="whitespace-nowrap">{fmtTime(s.created_at)}</td>
                  <td class="whitespace-nowrap">
                    {s.removed_at ? `${fmtTime(s.removed_at)} by ${s.removed_by}` : "–"}
                  </td>
                  <td class="text-right whitespace-nowrap">
                    {#if !s.removed_at}
                      {#if confirmLift === s.id}
                        <button class="btn btn-xs btn-error" onclick={() => lift(s.id)}>Confirm lift</button>
                        <button class="btn btn-xs btn-ghost" onclick={() => (confirmLift = null)}>Cancel</button>
                      {:else}
                        <button class="btn btn-xs" onclick={() => (confirmLift = s.id)}>Lift</button>
                      {/if}
                    {/if}
                  </td>
                </tr>
              {:else}
                <tr><td colspan="7" class="opacity-60">Nothing suppressed.</td></tr>
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
</div>
