import { useCallback, useEffect, useRef } from "react";
import type { CSSProperties, KeyboardEvent, ReactNode, RefObject } from "react";
import { ModalBackdrop } from "./ModalBackdrop";
import {
  FOCUS_CONTAINER,
  focusableWithin,
  modalDialogClass,
  modalWrapperClass,
  nextTrapIndex,
  type ModalPlacement,
} from "./modalScaffold";

interface ModalProps {
  /**
   * Accessible name for the dialog, announced when it opens. Required — a
   * `role="dialog"` with no name is read out as just "dialog".
   */
  label: string;
  onClose: () => void;
  children: ReactNode;
  /** Centred, or dropped from the top like a command palette. Default centred. */
  placement?: ModalPlacement;
  /**
   * Whether Escape closes the dialog. Off for the settings dialog, which is not
   * dismissible by accident on purpose — see the note on its call site.
   */
  closeOnEscape?: boolean;
  /** Whether a click on the backdrop closes the dialog. */
  closeOnBackdropClick?: boolean;
  /** Overlay dim. */
  backdropClassName?: string;
  /** Classes for the dialog box, on top of the shared surface styling. */
  className?: string;
  style?: CSSProperties;
  /**
   * Control to focus when the dialog opens. Defaults to the first focusable
   * element, which is right for a dialog that opens onto buttons but wrong for
   * one that opens onto a search field sitting after a row of mode toggles.
   */
  initialFocusRef?: RefObject<HTMLElement | null>;
}

/**
 * Shared shell for the app's modal dialogs: overlay, dim, centring, dialog
 * semantics, optional dismissal, and a focus trap.
 *
 * Six components had grown their own copy of the first four of those and none
 * had the fifth, so a keyboard or screen-reader user could Tab straight out of
 * an open dialog and into the page behind it. The trap is the reason this is a
 * component rather than a set of class-name constants: it needs the dialog
 * element, and the only way to guarantee every dialog has one is to own it.
 *
 * The trap does three things.
 *
 * 1. **On open** focus moves into the dialog — `initialFocusRef` if given, else
 *    the first focusable control, else the dialog box itself.
 * 2. **While open** Tab and Shift+Tab wrap at the ends of the dialog's focusable
 *    list instead of walking out of it. Only the ends are intercepted; the
 *    browser still handles movement within the list (see {@link nextTrapIndex}).
 * 3. **On close** focus returns to whatever held it when the dialog opened,
 *    normally the control that triggered it. Without this, closing a dialog
 *    drops focus onto `<body>` and the next Tab restarts from the top of the
 *    page.
 *
 * This is a real trap, not a suggestion — it does not attempt to constrain focus
 * moved by the mouse or by the browser's own address-bar cycle, which is the
 * conventional scope and matches what `aria-modal` promises.
 */
export function Modal({
  label,
  onClose,
  children,
  placement = "center",
  closeOnEscape = true,
  closeOnBackdropClick = true,
  backdropClassName = "bg-black/50",
  className = "",
  style,
  initialFocusRef,
}: ModalProps) {
  const dialogRef = useRef<HTMLDivElement>(null);

  // Deliberately mount-only: the dialog claims focus when it opens and hands it
  // back when it closes. `initialFocusRef` and `onClose` are read at those two
  // moments, so re-running on their identity would re-steal focus mid-edit.
  // biome-ignore lint/correctness/useExhaustiveDependencies: see above
  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    const restoreTo = document.activeElement;
    (initialFocusRef?.current ?? focusableWithin(dialog)[0] ?? dialog).focus();
    return () => {
      // `isConnected` guards the case where the trigger was itself unmounted
      // while the dialog was open — focusing a detached node silently sends
      // focus to <body>, which is worse than leaving it where it is.
      if (restoreTo instanceof HTMLElement && restoreTo !== document.body && restoreTo.isConnected) {
        restoreTo.focus();
      }
    };
  }, []);

  const handleKeyDown = useCallback(
    (e: KeyboardEvent<HTMLDivElement>) => {
      if (e.key === "Escape" && closeOnEscape) {
        e.preventDefault();
        // Stop here rather than letting Escape reach the view underneath, where
        // it means "navigate back".
        e.stopPropagation();
        onClose();
        return;
      }
      if (e.key !== "Tab") return;
      const dialog = dialogRef.current;
      if (!dialog) return;
      const items = focusableWithin(dialog);
      const active = document.activeElement;
      const target = nextTrapIndex(
        items.length,
        active instanceof HTMLElement ? items.indexOf(active) : -1,
        e.shiftKey,
      );
      if (target === null) return;
      e.preventDefault();
      (target === FOCUS_CONTAINER ? dialog : items[target]).focus();
    },
    [closeOnEscape, onClose],
  );

  return (
    <div className={modalWrapperClass(placement, closeOnBackdropClick ? null : backdropClassName)}>
      {closeOnBackdropClick && <ModalBackdrop onClose={onClose} className={backdropClassName} />}
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label={label}
        tabIndex={-1}
        onKeyDown={handleKeyDown}
        className={modalDialogClass(className)}
        style={style}
      >
        {children}
      </div>
    </div>
  );
}
