interface Props {
  onClose: () => void;
  /** Extra classes for the overlay tint. Defaults to the standard dim. */
  className?: string;
}

/**
 * Click-to-dismiss backdrop for the modal overlays.
 *
 * The click target is a real <button> rather than a click handler on the wrapper
 * div, so it is a control the platform already understands. Dismissing by mouse
 * this way is a convenience — {@link ./Modal} only renders this for dialogs that
 * also close on Escape — so the button is kept out of the tab order with
 * tabIndex={-1} instead of adding a second, redundant tab stop before the dialog.
 * Being out of the tab order also keeps it out of the focus trap's reach, which
 * is what stops Tab from landing on the page dim.
 *
 * Renders absolutely inside the modal's `fixed inset-0` wrapper, so the dialog
 * box itself needs `relative` (or any positioning) to paint above it. It also
 * carries the overlay dim; a dialog with no backdrop has the dim on the wrapper
 * instead. Prefer {@link ./Modal} over reaching for this directly.
 */
export function ModalBackdrop({ onClose, className = "bg-black/50" }: Props) {
  return (
    <button
      type="button"
      aria-label="Close dialog"
      tabIndex={-1}
      className={`absolute inset-0 w-full h-full cursor-default ${className}`}
      onClick={onClose}
    />
  );
}
