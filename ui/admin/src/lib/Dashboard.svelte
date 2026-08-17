<script>
  import { api } from "./api.svelte.js";

  let data = $state(null);
  let error = $state("");

  $effect(() => {
    api("/overview")
      .then((d) => (data = d))
      .catch((e) => (error = e.message));
  });

  // CSS-only bars, no chart library — nothing here justifies one.
  const maxDay = $derived(
    data
      ? Math.max(
          1,
          ...data.by_day.map((d) => d.sent + d.failed + d.suppressed + d.queued),
        )
      : 1,
  );

  function statusOf(name) {
    return data?.by_status.find((s) => s.status === name);
  }
</script>

{#if error}
  <div class="alert alert-error">{error}</div>
{:else if !data}
  <span class="loading loading-spinner"></span>
{:else}
  <div class="flex flex-col gap-4">
    <div class="stats stats-vertical sm:stats-horizontal bg-base-100 border border-base-300 w-full">
      <div class="stat">
        <!-- "Handed to relay", not "sent": the count is messages the
             smarthost accepted, which is the last thing postbud sees. -->
        <div class="stat-title">Handed to relay, last 24 h</div>
        <div class="stat-value text-success">{statusOf("sent")?.last_24h ?? 0}</div>
        <div class="stat-desc">{statusOf("sent")?.total ?? 0} all time</div>
      </div>
      <div class="stat">
        <div class="stat-title">Queue</div>
        <div class="stat-value">{data.queue_depth}</div>
        <div class="stat-desc">
          {#if data.queue_due > 0}
            <span class="text-warning">{data.queue_due} due now</span>
          {:else}
            nothing overdue
          {/if}
        </div>
      </div>
      <div class="stat">
        <div class="stat-title">Failed, last 7 d</div>
        <div class="stat-value {statusOf('failed')?.last_7d ? 'text-error' : ''}">
          {statusOf("failed")?.last_7d ?? 0}
        </div>
        <div class="stat-desc">{statusOf("failed")?.total ?? 0} all time</div>
      </div>
      <div class="stat">
        <div class="stat-title">Suppressed addresses</div>
        <div class="stat-value">{data.active_suppressions}</div>
        <div class="stat-desc">{data.bounces_7d} bounces last 7 d</div>
      </div>
    </div>

    {#if data.unmatched_bounces > 0}
      <div class="alert alert-warning text-sm">
        {data.unmatched_bounces} bounce report(s) could not be joined to a
        message. A rising number means queue ids are not captured on the way
        out — see the Bounces tab.
      </div>
    {/if}

    <div class="card bg-base-100 border border-base-300">
      <div class="card-body">
        <h2 class="card-title text-base">Last 14 days</h2>
        {#if data.by_day.length === 0}
          <p class="text-sm opacity-70">No messages yet.</p>
        {:else}
          <div class="flex items-end gap-1 h-32">
            {#each data.by_day as d (d.day)}
              {@const total = d.sent + d.failed + d.suppressed + d.queued}
              <div
                class="flex-1 flex flex-col justify-end h-full tooltip"
                data-tip={`${d.day}: ${d.sent} handed to relay, ${d.failed} failed, ${d.suppressed} suppressed, ${d.queued} queued`}
              >
                <div class="w-full bg-error" style="height:{((d.failed / maxDay) * 100).toFixed(1)}%"></div>
                <div class="w-full bg-warning" style="height:{(((d.suppressed + d.queued) / maxDay) * 100).toFixed(1)}%"></div>
                <div class="w-full bg-success" style="height:{((d.sent / maxDay) * 100).toFixed(1)}%"></div>
                <div class="w-full text-center text-[0.6rem] opacity-60 mt-1">
                  {total}
                </div>
              </div>
            {/each}
          </div>
        {/if}
      </div>
    </div>

    <div class="card bg-base-100 border border-base-300">
      <div class="card-body">
        <h2 class="card-title text-base">Per tenant</h2>
        <div class="overflow-x-auto">
          <table class="table table-sm">
            <thead>
              <tr><th>Tenant</th><th class="text-right">Last 7 d</th><th class="text-right">Total</th></tr>
            </thead>
            <tbody>
              {#each data.by_tenant as t (t.tenant)}
                <tr>
                  <td>{t.tenant}</td>
                  <td class="text-right">{t.last_7d}</td>
                  <td class="text-right">{t.total}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
{/if}
