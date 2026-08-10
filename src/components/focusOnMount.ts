/**
 * Callback ref that focuses an element when it mounts.
 *
 * Replaces the `autoFocus` attribute on inline edit fields (rename boxes, comment
 * editors, the hex byte editor, the address-history filter). Those fields are all
 * rendered *in response to a user action*, so focusing them is correct UX —
 * `autoFocus` is just the wrong mechanism for it, and it is what `a11y/noAutofocus`
 * flags. Behaviour is identical: React implements `autoFocus` as a focus() call on
 * mount, which is exactly what this does.
 *
 * Must stay a module-level (stable-identity) function. An inline arrow would be a
 * new function on every render, and React detaches/reattaches callback refs whose
 * identity changed — which would re-focus the field mid-typing.
 *
 * Deliberately not used for fields that are visible on first paint; those should
 * not steal focus at all.
 */
export function focusOnMount(el: HTMLElement | null): void {
  el?.focus();
}
