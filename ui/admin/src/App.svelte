<script>
  import { auth, api } from "./lib/api.svelte.js";
  import Dashboard from "./lib/Dashboard.svelte";
  import Messages from "./lib/Messages.svelte";
  import Suppressions from "./lib/Suppressions.svelte";
  import Tenants from "./lib/Tenants.svelte";
  import Bounces from "./lib/Bounces.svelte";

  const sections = [
    { id: "dashboard", label: "Dashboard", component: Dashboard },
    { id: "messages", label: "Messages", component: Messages },
    { id: "suppressions", label: "Suppressions", component: Suppressions },
    { id: "tenants", label: "Tenants", component: Tenants },
    { id: "bounces", label: "Bounces", component: Bounces },
  ];

  let section = $state(location.hash.slice(1) || "dashboard");
  $effect(() => {
    const onHash = () => (section = location.hash.slice(1) || "dashboard");
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  });

  // Login state. The token is validated by actually using it — one
  // overview call — so a wrong token never gets stored.
  let tokenInput = $state("");
  let loginError = $state("");
  let checking = $state(false);

  async function login(event) {
    event.preventDefault();
    checking = true;
    loginError = "";
    auth.set(tokenInput.trim());
    try {
      await api("/overview");
      tokenInput = "";
    } catch (err) {
      loginError =
        err.status === 503
          ? "The admin surface is not configured on the server (ADMIN_TOKEN is unset)."
          : "That token was not accepted.";
    } finally {
      checking = false;
    }
  }

  const Active = $derived(
    sections.find((s) => s.id === section)?.component ?? Dashboard,
  );
</script>

{#if !auth.token}
  <div class="min-h-screen flex items-center justify-center bg-base-200 p-4">
    <div class="card bg-base-100 border border-base-300 w-full max-w-sm">
      <form class="card-body gap-4" onsubmit={login}>
        <div>
          <h1 class="card-title text-2xl">postbud</h1>
          <p class="text-sm opacity-70">outbound mail, administered</p>
        </div>
        <label class="form-control">
          <span class="label-text mb-1">Admin token</span>
          <input
            type="password"
            class="input input-bordered w-full"
            bind:value={tokenInput}
            autocomplete="off"
            required
          />
        </label>
        {#if loginError}
          <div class="alert alert-error text-sm py-2">{loginError}</div>
        {/if}
        <button class="btn btn-primary" disabled={checking}>
          {#if checking}<span class="loading loading-spinner loading-sm"></span>{/if}
          Sign in
        </button>
      </form>
    </div>
  </div>
{:else}
  <div class="min-h-screen bg-base-200">
    <div class="navbar bg-base-100 shadow-sm px-4">
      <div class="flex-1 flex items-center gap-6">
        <span class="text-lg font-bold">postbud</span>
        <nav class="flex gap-1 overflow-x-auto">
          {#each sections as s (s.id)}
            <a
              href={"#" + s.id}
              class="btn btn-sm {section === s.id ? 'btn-primary' : 'btn-ghost'}"
            >
              {s.label}
            </a>
          {/each}
        </nav>
      </div>
      <button class="btn btn-ghost btn-sm" onclick={() => auth.clear()}>
        Sign out
      </button>
    </div>
    <main class="p-4 max-w-6xl mx-auto">
      <Active />
    </main>
  </div>
{/if}
