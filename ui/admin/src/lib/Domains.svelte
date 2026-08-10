<script>
  import { api, me, fmtTime } from "./api.svelte.js";

  let rows = $state(null);
  let error = $state("");
  let notice = $state("");
  let confirmEnd = $state(null);
  let copied = $state("");

  // Add form.
  let domain = $state("");
  let selector = $state("pb2026a");
  let publicKey = $state("");
  let spf = $state("");
  let mx = $state("");

  async function load() {
    error = "";
    try {
      rows = await api("/domains");
    } catch (e) {
      error = e.message;
    }
  }

  async function add(event) {
    event.preventDefault();
    error = "";
    notice = "";
    try {
      const created = await api("/domains", {
        method: "POST",
        body: JSON.stringify({
          domain: domain.trim(),
          dkim_selector: selector.trim(),
          dkim_public_key: publicKey.trim(),
          spf_expected: spf.trim() || null,
          mx_expected: mx.trim() || null,
        }),
      });
      notice = `${created.domain} registered — the worker checks it within a minute, then every 15 minutes until all records are green.`;
      domain = "";
      publicKey = "";
      spf = "";
      mx = "";
      await load();
    } catch (e) {
      error = e.message;
    }
  }

  async function endDomain(id) {
    error = "";
    try {
      await api(`/domains/${id}`, { method: "DELETE" });
      confirmEnd = null;
      await load();
    } catch (e) {
      error = e.message;
      confirmEnd = null;
    }
  }

  async function copy(value, key) {
    try {
      await navigator.clipboard.writeText(value);
    } catch {
      // Clipboard API can be denied; fall back to a prompt-free select.
      const ta = document.createElement("textarea");
      ta.value = value;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
    }
    copied = key;
    setTimeout(() => (copied = ""), 1500);
  }

  function statusOf(check, kind) {
    if (!check) return null;
    return check[`${kind}_status`];
  }
  function observedOf(check, kind) {
    return check?.[`${kind}_observed`];
  }
  const badgeClass = {
    ok: "badge-success",
    missing: "badge-warning",
    mismatch: "badge-error",
  };

  $effect(() => {
    load();
  });
</script>

<div class="flex flex-col gap-4">
  {#if notice}<div class="alert alert-success text-sm py-2">{notice}</div>{/if}
  {#if error}<div class="alert alert-error text-sm py-2">{error}</div>{/if}

  {#if !rows}
    <span class="loading loading-spinner"></span>
  {:else}
    {#each rows as d (d.id)}
      <div class="card bg-base-100 border {d.check?.valid ? 'border-success/40' : 'border-base-300'}">
        <div class="card-body gap-3">
          <div class="flex items-start justify-between gap-2 flex-wrap">
            <div>
              <h2 class="card-title text-base">{d.domain}</h2>
              <p class="text-xs opacity-60">
                {#if d.check}
                  last checked {fmtTime(d.check.checked_at)} —
                  {#if d.check.valid}
                    <span class="text-success font-semibold">verified</span>, re-checked daily
                  {:else}
                    <span class="text-warning font-semibold">not verified</span>, re-checked every 15 min
                  {/if}
                {:else}
                  never checked yet — the worker picks it up within a minute
                {/if}
              </p>
            </div>
            {#if me.write}
              <div>
                {#if confirmEnd === d.id}
                  <button class="btn btn-xs btn-error" onclick={() => endDomain(d.id)}>Confirm remove</button>
                  <button class="btn btn-xs btn-ghost" onclick={() => (confirmEnd = null)}>Cancel</button>
                {:else}
                  <button class="btn btn-xs" onclick={() => (confirmEnd = d.id)}>Remove</button>
                {/if}
              </div>
            {/if}
          </div>

          <p class="text-sm opacity-70">
            Publish these records in the DNS zone for
            <code>{d.domain.split(".").slice(-2).join(".")}</code>. Values must
            match exactly — the checker compares what DNS actually serves,
            including that the DKIM key is the one the relay signs with.
          </p>

          <div class="overflow-x-auto">
            <table class="table table-sm">
              <thead>
                <tr><th>Status</th><th>Type</th><th class="hidden sm:table-cell">Name</th><th>Value</th><th></th></tr>
              </thead>
              <tbody>
                {#each d.records as r (r.kind)}
                  {@const st = statusOf(d.check, r.kind)}
                  <tr>
                    <td>
                      {#if st}
                        <span class="badge badge-sm {badgeClass[st] ?? ''}" title={observedOf(d.check, r.kind)}>{st}</span>
                      {:else}
                        <span class="badge badge-sm badge-ghost">pending</span>
                      {/if}
                    </td>
                    <td>{r.type}</td>
                    <td class="hidden sm:table-cell"><code class="text-xs break-all">{r.name}</code></td>
                    <td class="max-w-xs sm:max-w-md">
                      <code class="text-xs break-all line-clamp-2" title={r.value}>{r.value}</code>
                      {#if st === "mismatch" && observedOf(d.check, r.kind)}
                        <div class="text-xs text-error mt-1">seen: {observedOf(d.check, r.kind)}</div>
                      {/if}
                    </td>
                    <td class="text-right">
                      <button class="btn btn-xs" onclick={() => copy(r.value, d.id + r.kind)}>
                        {copied === d.id + r.kind ? "✓" : "Copy"}
                      </button>
                    </td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    {:else}
      <div class="card bg-base-100 border border-base-300">
        <div class="card-body">
          <p class="text-sm opacity-70">
            No sending domains registered. Register the domains your tenants
            send as, and the worker will verify their DNS continuously.
          </p>
        </div>
      </div>
    {/each}
  {/if}

  {#if me.write}
    <div class="card bg-base-100 border border-base-300">
      <div class="card-body gap-3">
        <h2 class="card-title text-base">Register domain</h2>
        <p class="text-sm opacity-70">
          The DKIM public key is the <code>p=</code> value from the relay's
          key file for this domain (<code>/etc/dkimkeys/&lt;domain&gt;.txt</code>) —
          the checker verifies DNS serves <em>exactly this key</em>, so a
          wrong paste shows up as a mismatch, never as a false green.
        </p>
        <form class="flex flex-col gap-2" onsubmit={add}>
          <div class="flex flex-wrap gap-2">
            <label class="form-control">
              <span class="label-text text-xs mb-1">Domain</span>
              <input class="input input-bordered input-sm w-56" bind:value={domain} required placeholder="mail.example.com" />
            </label>
            <label class="form-control">
              <span class="label-text text-xs mb-1">DKIM selector</span>
              <input class="input input-bordered input-sm w-32" bind:value={selector} required />
            </label>
            <label class="form-control">
              <span class="label-text text-xs mb-1">MX target (optional)</span>
              <input class="input input-bordered input-sm w-56" bind:value={mx} placeholder="relay hostname for bounces" />
            </label>
          </div>
          <label class="form-control">
            <span class="label-text text-xs mb-1">DKIM public key (p= value)</span>
            <textarea class="textarea textarea-bordered textarea-sm font-mono text-xs" rows="3" bind:value={publicKey} required></textarea>
          </label>
          <label class="form-control">
            <span class="label-text text-xs mb-1">Expected SPF (blank = installation default)</span>
            <input class="input input-bordered input-sm font-mono" bind:value={spf} placeholder="v=spf1 ip4:… -all" />
          </label>
          <div><button class="btn btn-sm btn-primary">Register</button></div>
        </form>
      </div>
    </div>
  {/if}
</div>
