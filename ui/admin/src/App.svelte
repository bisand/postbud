<script>
  import { auth, api } from "./lib/api.svelte.js";
  import { icons } from "./lib/icons.js";
  import { THEMES, themePref, apply as applyTheme } from "./lib/theme.svelte.js";
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

  // The stored theme is applied before first paint of anything below.
  applyTheme();

  // Hash routing with one optional segment: `#messages/{id}` is the
  // detail view INSIDE the messages section. Putting the detail in the
  // route is what makes the browser's Back button return to the list
  // instead of leaving the app.
  function parseHash() {
    const parts = location.hash.slice(1).split("/");
    return { section: parts[0] || "dashboard", param: parts[1] || null };
  }
  let route = $state(parseHash());
  const section = $derived(route.section);
  $effect(() => {
    const onHash = () => (route = parseHash());
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

{#snippet themePicker()}
  <label class="flex items-center gap-2 px-1">
    <span class="opacity-70 shrink-0">{@html icons.theme}</span>
    <select
      class="select select-bordered select-sm grow min-w-0"
      aria-label="Theme"
      value={themePref.value}
      onchange={(e) => themePref.set(e.target.value)}
    >
      {#each THEMES as t (t)}
        <option value={t}>{t}</option>
      {/each}
    </select>
  </label>
{/snippet}

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
        <div class="text-sm">{@render themePicker()}</div>
      </form>
    </div>
  </div>
{:else}
  <div class="min-h-screen flex bg-base-200">
    <!-- Vertical menu. Icons always; labels from sm up. -->
    <aside
      class="w-14 sm:w-52 shrink-0 bg-base-100 border-r border-base-300
             flex flex-col sticky top-0 h-screen"
    >
      <div class="px-3 py-4 flex items-center gap-2">
        <span class="text-primary">{@html icons.dashboard}</span>
        <span class="text-lg font-bold hidden sm:inline">postbud</span>
      </div>

      <nav class="flex flex-col gap-1 px-2 grow">
        {#each sections as s (s.id)}
          <a
            href={"#" + s.id}
            title={s.label}
            class="btn btn-sm justify-start gap-3 {section === s.id
              ? 'btn-primary'
              : 'btn-ghost'}"
          >
            {@html icons[s.id]}
            <span class="hidden sm:inline">{s.label}</span>
          </a>
        {/each}
      </nav>

      <div class="p-2 flex flex-col gap-2 border-t border-base-300 text-sm">
        <div class="hidden sm:block">{@render themePicker()}</div>
        <button
          class="btn btn-ghost btn-sm justify-start gap-3"
          title="Sign out"
          onclick={() => auth.clear()}
        >
          {@html icons.signout}
          <span class="hidden sm:inline">Sign out</span>
        </button>
      </div>
    </aside>

    <main class="p-4 grow max-w-6xl min-w-0">
      <Active param={route.param} />
    </main>
  </div>
{/if}
