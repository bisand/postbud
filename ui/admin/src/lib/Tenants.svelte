<script>
  import { api, fmtTime } from "./api.svelte.js";

  let rows = $state(null);
  let error = $state("");

  // A freshly minted key, shown exactly once. It exists only in this
  // variable and on the screen; postbud stores its digest.
  let mintedKey = $state(null);
  let mintedFor = $state("");

  // Create form.
  let name = $state("");
  let domains = $state("");
  let note = $state("");

  // Per-row edit + two-step confirms.
  let editDomains = $state(null); // { id, value }
  let confirmRotate = $state(null);
  let confirmActive = $state(null);

  async function load() {
    error = "";
    try {
      rows = await api("/tenants");
    } catch (e) {
      error = e.message;
    }
  }

  async function create(event) {
    event.preventDefault();
    error = "";
    try {
      const created = await api("/tenants", {
        method: "POST",
        body: JSON.stringify({
          name,
          from_domains: domains.split(",").map((d) => d.trim()).filter(Boolean),
          note: note || null,
        }),
      });
      mintedKey = created.api_key;
      mintedFor = created.name;
      name = "";
      domains = "";
      note = "";
      await load();
    } catch (e) {
      error = e.message;
    }
  }

  async function rotate(id, tenantName) {
    error = "";
    try {
      const res = await api(`/tenants/${id}/rotate-key`, { method: "POST" });
      mintedKey = res.api_key;
      mintedFor = tenantName;
      confirmRotate = null;
    } catch (e) {
      error = e.message;
    }
  }

  async function setActive(id, active) {
    error = "";
    try {
      await api(`/tenants/${id}/active`, {
        method: "POST",
        body: JSON.stringify({ active }),
      });
      confirmActive = null;
      await load();
    } catch (e) {
      error = e.message;
    }
  }

  async function saveDomains() {
    error = "";
    try {
      await api(`/tenants/${editDomains.id}/domains`, {
        method: "PUT",
        body: JSON.stringify({
          from_domains: editDomains.value.split(",").map((d) => d.trim()).filter(Boolean),
        }),
      });
      editDomains = null;
      await load();
    } catch (e) {
      error = e.message;
    }
  }

  $effect(() => {
    load();
  });
</script>

<div class="flex flex-col gap-4">
  {#if mintedKey}
    <div class="card bg-base-100 border-2 border-warning">
      <div class="card-body gap-2">
        <p class="font-semibold">
          API key for <code>{mintedFor}</code> — shown once, store it now:
        </p>
        <code class="bg-base-200 rounded p-2 text-sm break-all select-all">{mintedKey}</code>
        <p class="text-xs opacity-70">
          postbud keeps only a digest of this key and cannot show it again.
          Any previous key for this tenant stopped working the moment this
          one was minted.
        </p>
        <div>
          <button class="btn btn-sm btn-warning" onclick={() => (mintedKey = null)}>
            I have stored it
          </button>
        </div>
      </div>
    </div>
  {/if}

  {#if error}<div class="alert alert-error text-sm py-2">{error}</div>{/if}

  <div class="card bg-base-100 border border-base-300">
    <div class="card-body gap-3">
      <h2 class="card-title text-base">Tenants</h2>
      {#if !rows}
        <span class="loading loading-spinner"></span>
      {:else}
        <div class="overflow-x-auto">
          <table class="table table-sm">
            <thead>
              <tr><th>Name</th><th>Sending domains</th><th>7 d / total</th><th>Since</th><th>State</th><th class="text-right">Actions</th></tr>
            </thead>
            <tbody>
              {#each rows as t (t.id)}
                <tr class={t.active ? "" : "opacity-50"}>
                  <td>
                    {t.name}
                    {#if t.note}<div class="text-xs opacity-60">{t.note}</div>{/if}
                  </td>
                  <td>
                    {#if editDomains?.id === t.id}
                      <div class="flex gap-1">
                        <input class="input input-bordered input-xs w-48" bind:value={editDomains.value} />
                        <button class="btn btn-xs btn-primary" onclick={saveDomains}>Save</button>
                        <button class="btn btn-xs btn-ghost" onclick={() => (editDomains = null)}>Cancel</button>
                      </div>
                    {:else}
                      <code class="text-xs">{t.from_domains.join(", ")}</code>
                      <button
                        class="btn btn-xs btn-ghost"
                        onclick={() => (editDomains = { id: t.id, value: t.from_domains.join(", ") })}
                      >
                        Edit
                      </button>
                    {/if}
                  </td>
                  <td class="whitespace-nowrap">{t.messages_7d} / {t.messages_total}</td>
                  <td class="whitespace-nowrap">{fmtTime(t.created_at)}</td>
                  <td>
                    <span class="badge badge-sm {t.active ? 'badge-success' : 'badge-neutral'}">
                      {t.active ? "active" : "inactive"}
                    </span>
                  </td>
                  <td class="text-right whitespace-nowrap">
                    {#if confirmRotate === t.id}
                      <button class="btn btn-xs btn-error" onclick={() => rotate(t.id, t.name)}>
                        Confirm — old key dies now
                      </button>
                      <button class="btn btn-xs btn-ghost" onclick={() => (confirmRotate = null)}>Cancel</button>
                    {:else if confirmActive === t.id}
                      <button class="btn btn-xs btn-error" onclick={() => setActive(t.id, !t.active)}>
                        Confirm {t.active ? "deactivate" : "reactivate"}
                      </button>
                      <button class="btn btn-xs btn-ghost" onclick={() => (confirmActive = null)}>Cancel</button>
                    {:else}
                      <button class="btn btn-xs" onclick={() => (confirmRotate = t.id)}>Rotate key</button>
                      <button class="btn btn-xs" onclick={() => (confirmActive = t.id)}>
                        {t.active ? "Deactivate" : "Reactivate"}
                      </button>
                    {/if}
                  </td>
                </tr>
              {:else}
                <tr><td colspan="6" class="opacity-60">No tenants yet.</td></tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </div>
  </div>

  <div class="card bg-base-100 border border-base-300">
    <div class="card-body gap-3">
      <h2 class="card-title text-base">New tenant</h2>
      <p class="text-sm opacity-70">
        One tenant per sending system. Domains are exact — subdomains are
        not implied, list each one.
      </p>
      <form class="flex flex-wrap gap-2 items-end" onsubmit={create}>
        <label class="form-control">
          <span class="label-text text-xs mb-1">Name</span>
          <input class="input input-bordered input-sm" bind:value={name} required placeholder="my-app-prod" />
        </label>
        <label class="form-control">
          <span class="label-text text-xs mb-1">Sending domains (comma-separated)</span>
          <input class="input input-bordered input-sm w-64" bind:value={domains} required placeholder="example.com, mail.example.com" />
        </label>
        <label class="form-control">
          <span class="label-text text-xs mb-1">Note</span>
          <input class="input input-bordered input-sm" bind:value={note} />
        </label>
        <button class="btn btn-sm btn-primary">Create</button>
      </form>
    </div>
  </div>
</div>
