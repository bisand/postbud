<script>
  import { auth, api, me } from "./lib/api.svelte.js";
  import { fetchConfig, beginLogin, completeLogin } from "./lib/oidc.js";
  import { icons } from "./lib/icons.js";
  import { THEMES, themePref, apply as applyTheme } from "./lib/theme.svelte.js";
  import Dashboard from "./lib/Dashboard.svelte";
  import Messages from "./lib/Messages.svelte";
  import Suppressions from "./lib/Suppressions.svelte";
  import Tenants from "./lib/Tenants.svelte";
  import Bounces from "./lib/Bounces.svelte";
  import Users from "./lib/Users.svelte";

  const sections = [
    { id: "dashboard", label: "Dashboard", component: Dashboard },
    { id: "messages", label: "Messages", component: Messages },
    { id: "suppressions", label: "Suppressions", component: Suppressions },
    { id: "tenants", label: "Tenants", component: Tenants },
    { id: "bounces", label: "Bounces", component: Bounces },
    { id: "users", label: "Users", component: Users },
  ];

  // Who am I — for display and for hiding controls a viewer cannot use.
  // The server enforces regardless.
  $effect(() => {
    if (auth.token && !me.value) {
      api("/me").then((m) => me.set(m)).catch(() => {});
    }
    if (!auth.token) me.set(null);
  });

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

  // Login state. Credentials are validated by actually using them — one
  // overview call — so a bad token never gets stored, and an OIDC login
  // by someone off the allowlist gets a clear answer instead of a wall
  // of 401s.
  let tokenInput = $state("");
  let loginError = $state("");
  let checking = $state(false);
  let config = $state(null);
  let showTokenForm = $state(false);
  const oidcCfg = $derived(config?.oidc ?? null);

  async function validateSession() {
    try {
      await api("/overview");
      return true;
    } catch (err) {
      loginError =
        err.status === 503
          ? "The admin surface is not configured on the server."
          : err.status === 401 && oidcCfg?.enabled
            ? "You are signed in, but this account has no access here."
            : "That token was not accepted.";
      return false;
    }
  }

  // On load: finish an OIDC callback if this is one, then learn whether
  // OIDC is available at all (drives which login button to show).
  $effect(() => {
    (async () => {
      try {
        const idToken = await completeLogin();
        if (idToken) {
          checking = true;
          auth.set(idToken);
          await validateSession();
        }
      } catch (err) {
        loginError = err.message;
      } finally {
        checking = false;
      }
      config = await fetchConfig();
    })();
  });

  async function login(event) {
    event.preventDefault();
    checking = true;
    loginError = "";
    auth.set(tokenInput.trim());
    if (await validateSession()) tokenInput = "";
    checking = false;
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
      <div class="card-body gap-4">
        <div class="flex items-center gap-3">
          <span class="text-primary">{@html icons.logo}</span>
          <div>
            <h1 class="card-title text-2xl">postbud</h1>
            <p class="text-sm opacity-70">outbound mail, administered</p>
          </div>
        </div>

        {#if loginError}
          <div class="alert alert-error text-sm py-2">{loginError}</div>
        {/if}

        {#if oidcCfg === null}
          <span class="loading loading-spinner"></span>
        {:else}
          {#if oidcCfg.enabled}
            <button
              class="btn btn-primary"
              disabled={checking}
              onclick={() => beginLogin(oidcCfg)}
            >
              {#if checking}<span class="loading loading-spinner loading-sm"></span>{/if}
              Sign in with {new URL(oidcCfg.issuer).host}
            </button>
          {/if}

          {#if !oidcCfg.enabled || showTokenForm}
            <form class="flex flex-col gap-4" onsubmit={login}>
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
              <button class="btn" disabled={checking}>
                {#if checking}<span class="loading loading-spinner loading-sm"></span>{/if}
                Sign in with token
              </button>
            </form>
          {:else}
            <button
              class="btn btn-ghost btn-xs self-start"
              onclick={() => (showTokenForm = true)}
            >
              Use the admin token instead
            </button>
          {/if}
        {/if}

        <div class="text-sm">{@render themePicker()}</div>
        {#if config?.version}
          <p class="text-xs opacity-50 text-center">{config.version}</p>
        {/if}
      </div>
    </div>
  </div>
{:else}
  <div class="min-h-screen flex flex-col sm:flex-row bg-base-200">
    <!-- Small screens: a sticky top bar with icon tabs. The vertical
         rail cost 15% of a phone's width; the tables want it more. -->
    <header
      class="sm:hidden sticky top-0 z-10 bg-base-100 border-b border-base-300
             flex items-center gap-1 px-2 py-1.5"
    >
      <span class="text-primary px-1 shrink-0">{@html icons.logo}</span>
      <nav class="flex gap-1 overflow-x-auto grow">
        {#each sections as s (s.id)}
          <a
            href={"#" + s.id}
            title={s.label}
            aria-label={s.label}
            class="btn btn-sm btn-square shrink-0 {section === s.id
              ? 'btn-primary'
              : 'btn-ghost'}"
          >
            {@html icons[s.id]}
          </a>
        {/each}
      </nav>
      <button
        class="btn btn-ghost btn-sm btn-square shrink-0"
        title="Sign out"
        aria-label="Sign out"
        onclick={() => auth.clear()}
      >
        {@html icons.signout}
      </button>
    </header>

    <!-- sm and up: the vertical menu, unchanged. -->
    <aside
      class="w-52 shrink-0 bg-base-100 border-r border-base-300
             hidden sm:flex flex-col sticky top-0 h-screen"
    >
      <div class="px-3 py-4 flex items-center gap-2">
        <span class="text-primary">{@html icons.logo}</span>
        <span class="text-lg font-bold">postbud</span>
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
            <span>{s.label}</span>
          </a>
        {/each}
      </nav>

      <div class="p-2 flex flex-col gap-2 border-t border-base-300 text-sm">
        {#if me.value}
          <div class="px-2 text-xs opacity-60 break-all">
            {me.value.actor}
            <span class="badge badge-xs ml-1">{me.value.role}</span>
          </div>
        {/if}
        <div>{@render themePicker()}</div>
        <button
          class="btn btn-ghost btn-sm justify-start gap-3"
          title="Sign out"
          onclick={() => auth.clear()}
        >
          {@html icons.signout}
          <span>Sign out</span>
        </button>
        {#if config?.version}
          <p class="px-2 text-xs opacity-50">{config.version}</p>
        {/if}
      </div>
    </aside>

    <main class="p-3 sm:p-4 grow max-w-6xl min-w-0">
      <Active param={route.param} />
    </main>
  </div>
{/if}
