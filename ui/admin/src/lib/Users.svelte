<script>
  import { api, me, fmtTime } from "./api.svelte.js";

  let rows = $state(null);
  let error = $state("");
  let notice = $state("");
  let includeEnded = $state(false);

  // Add form.
  let identifier = $state("");
  let role = $state("viewer");
  let note = $state("");

  // Two-step confirms, never window.confirm.
  let confirmEnd = $state(null);
  let confirmRole = $state(null); // { id, role }

  async function load() {
    error = "";
    try {
      rows = await api(`/users?include_ended=${includeEnded}`);
    } catch (e) {
      error = e.message;
    }
  }

  async function add(event) {
    event.preventDefault();
    error = "";
    notice = "";
    try {
      const created = await api("/users", {
        method: "POST",
        body: JSON.stringify({
          identifier: identifier.trim(),
          role,
          note: note || null,
        }),
      });
      notice = `${created.identifier} added as ${created.role}.`;
      identifier = "";
      note = "";
      await load();
    } catch (e) {
      error = e.message;
    }
  }

  async function setRole(id, newRole) {
    error = "";
    notice = "";
    try {
      await api(`/users/${id}/role`, {
        method: "POST",
        body: JSON.stringify({ role: newRole }),
      });
      confirmRole = null;
      await load();
    } catch (e) {
      error = e.message;
      confirmRole = null;
    }
  }

  async function endUser(id) {
    error = "";
    notice = "";
    try {
      await api(`/users/${id}`, { method: "DELETE" });
      notice = "Access ended. The row is kept — history, not deletion.";
      confirmEnd = null;
      await load();
    } catch (e) {
      error = e.message;
      confirmEnd = null;
    }
  }

  $effect(() => {
    load();
  });
</script>

<div class="flex flex-col gap-4">
  <div class="card bg-base-100 border border-base-300">
    <div class="card-body gap-3">
      <h2 class="card-title text-base">Users</h2>
      <p class="text-sm opacity-70">
        Who may operate this admin, decided here — the login provider only
        proves identity. <b>admin</b> can change everything;
        <b>viewer</b> sees everything and changes nothing. Removal ends the
        grant and keeps the row: who had access when is part of the record.
      </p>

      {#if notice}<div class="alert alert-success text-sm py-2">{notice}</div>{/if}
      {#if error}<div class="alert alert-error text-sm py-2">{error}</div>{/if}

      <label class="label cursor-pointer gap-2 self-start">
        <input
          type="checkbox"
          class="checkbox checkbox-sm"
          bind:checked={includeEnded}
          onchange={load}
        />
        <span class="label-text text-xs">Show ended grants (history)</span>
      </label>

      {#if !rows}
        <span class="loading loading-spinner"></span>
      {:else}
        <div class="overflow-x-auto">
          <table class="table table-sm">
            <thead>
              <tr><th>Identity</th><th>Role</th><th>Granted</th><th>Ended</th><th class="text-right"></th></tr>
            </thead>
            <tbody>
              {#each rows as u (u.id)}
                <tr class={u.ended_at ? "opacity-50" : ""}>
                  <td class="break-all">
                    {u.identifier}
                    {#if me.value && u.identifier.toLowerCase() === me.value.actor.toLowerCase()}
                      <span class="badge badge-xs badge-primary ml-1">you</span>
                    {/if}
                    {#if u.note}<div class="text-xs opacity-60">{u.note}</div>{/if}
                  </td>
                  <td>
                    <span class="badge badge-sm {u.role === 'admin' ? 'badge-primary' : 'badge-neutral'}">
                      {u.role}
                    </span>
                  </td>
                  <td class="whitespace-nowrap text-xs">
                    {fmtTime(u.created_at)}<br /><span class="opacity-60">by {u.created_by}</span>
                  </td>
                  <td class="whitespace-nowrap text-xs">
                    {#if u.ended_at}
                      {fmtTime(u.ended_at)}<br /><span class="opacity-60">by {u.ended_by}</span>
                    {:else}
                      –
                    {/if}
                  </td>
                  <td class="text-right whitespace-nowrap">
                    {#if !u.ended_at && me.write}
                      {#if confirmRole?.id === u.id}
                        <button class="btn btn-xs btn-error" onclick={() => setRole(u.id, confirmRole.role)}>
                          Confirm {confirmRole.role}
                        </button>
                        <button class="btn btn-xs btn-ghost" onclick={() => (confirmRole = null)}>Cancel</button>
                      {:else if confirmEnd === u.id}
                        <button class="btn btn-xs btn-error" onclick={() => endUser(u.id)}>
                          Confirm remove
                        </button>
                        <button class="btn btn-xs btn-ghost" onclick={() => (confirmEnd = null)}>Cancel</button>
                      {:else}
                        <button
                          class="btn btn-xs"
                          onclick={() =>
                            (confirmRole = { id: u.id, role: u.role === "admin" ? "viewer" : "admin" })}
                        >
                          Make {u.role === "admin" ? "viewer" : "admin"}
                        </button>
                        <button class="btn btn-xs" onclick={() => (confirmEnd = u.id)}>Remove</button>
                      {/if}
                    {/if}
                  </td>
                </tr>
              {:else}
                <tr>
                  <td colspan="5" class="opacity-60">
                    No users yet — the environment allowlist (or the admin
                    token) governs until the first one is added.
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </div>
  </div>

  {#if me.write}
    <div class="card bg-base-100 border border-base-300">
      <div class="card-body gap-3">
        <h2 class="card-title text-base">Add user</h2>
        <p class="text-sm opacity-70">
          The identity is an e-mail address (as the login provider reports
          it) or an OIDC subject id. The person must already be able to log
          in at the provider — postbud never stores passwords.
        </p>
        <form class="flex flex-wrap gap-2 items-end" onsubmit={add}>
          <label class="form-control">
            <span class="label-text text-xs mb-1">E-mail or subject id</span>
            <input class="input input-bordered input-sm w-64" bind:value={identifier} required />
          </label>
          <label class="form-control">
            <span class="label-text text-xs mb-1">Role</span>
            <select class="select select-bordered select-sm" bind:value={role}>
              <option value="viewer">viewer — read-only</option>
              <option value="admin">admin — full control</option>
            </select>
          </label>
          <label class="form-control">
            <span class="label-text text-xs mb-1">Note</span>
            <input class="input input-bordered input-sm" bind:value={note} />
          </label>
          <button class="btn btn-sm btn-primary">Add</button>
        </form>
      </div>
    </div>
  {/if}
</div>
