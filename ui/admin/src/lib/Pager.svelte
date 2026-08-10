<script>
  // The pager for every keyset-paged list: newer/older, the page number,
  // and the rows-per-page control.
  //
  // One component rather than three copies, because the three lists had
  // already drifted apart once and the page size has to mean the same
  // thing in all of them. `limit` is what the SERVER applied, not what
  // was asked for — showing the request would be a lie the moment it is
  // clamped.
  import { PAGE_SIZES, pageSize } from "./pagesize.svelte.js";

  let { pos, hasNext, limit = null, count = 0, onNewer, onOlder, onResize } = $props();

  function resize(event) {
    pageSize.set(event.target.value);
    onResize();
  }
</script>

<div class="flex items-center gap-2 flex-wrap">
  <button class="btn btn-sm" disabled={pos === 0} onclick={onNewer}>← Newer</button>
  <button class="btn btn-sm" disabled={!hasNext} onclick={onOlder}>Older →</button>

  <label class="flex items-center gap-1 text-xs opacity-70">
    <span class="hidden sm:inline">Rows</span>
    <select class="select select-xs" value={pageSize.value} onchange={resize}>
      {#each PAGE_SIZES as n}
        <option value={n}>{n}</option>
      {/each}
    </select>
  </label>

  <span class="text-xs opacity-60">
    page {pos + 1}{#if limit} · showing {count} of up to {limit}{/if}
  </span>
</div>
