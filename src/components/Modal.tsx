import { useCallback, useEffect, useRef } from "react";
import type { CSSProperties, KeyboardEvent, ReactNode, RefObject } from "react";
import { ModalBackdrop } from "./ModalBackdrop";
import {
  FOCUS_CONTAINER,
  focusableWithin,
  lockBodyScroll,
  modalDialogClass,
  modalNameAttrs,
  modalWrapperClass,
  nextTrapIndex,
  unlockBodyScroll,
  UNLOCKED,
  type ModalPlacement,
  type ScrollLockState,
} from "./modalScaffold";

/**
 * How the dialog is named. Exactly one of the two, never both and never
 * neither — a `role="dialog"` with no name is read out as just "dialog".
 *
 * Prefer `labelledBy`, pointing at the id of the dialog's own visible heading:
 * the announced name is then the heading text itself and cannot fall out of
 * step with it. `label` is for dialogs that have no heading to point at.
 */
type ModalNaming =
  | { label: string; labelledBy?: undefined }
  | { labelledBy: string; label?: undefined };

interface ModalBaseProps {
  onClose: () => void;
  children: ReactNode;
  /** Centred, or dropped from the top like a command palette. Default centred. */
  placement?: ModalPlacement;
  /**
   * Whether Escape closes the dialog. On by default, because Escape is what a
   * user expects of a dialog. Off for settings, and for the AI dialogs whenever
   * closing them would destroy something — see {@link accidentalDismissAllowed}
   * for the rule and the call sites for each dialog's reasoning.
   */
  closeOnEscape?: boolean;
  /** Whether a click on the backdrop closes the dialog. Same rule as Escape. */
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

type ModalProps = ModalBaseProps & ModalNaming;

/**
 * Lock state for `<body>` scrolling, shared by every mounted dialog.
 *
 * Module-level because the lock is a property of the document, not of any one
 * dialog: with two open, the first to close must not unlock the page. All the
 * decisions live in {@link lockBodyScroll} / {@link unlockBodyScroll}, which are
 * pure and tested; this variable only holds the value between them.
 */
let scrollLock: ScrollLockState = UNLOCKED;

/**
 * Shared shell for the app's modal dialogs: overlay, dim, centring, dialog
 * semantics, optional dismissal, a focus trap, and a body scroll lock.
 *
 * Six components had grown their own copy of the first four of those and none
 * had the last two, so a keyboard or screen-reader user could Tab straight out
 * of an open dialog and into the page behind it, and a wheel could scroll that
 * page while it was there. The trap is the reason this is a component rather
 * than a set of class-name constants: it needs the dialog element, and the only
 * way to guarantee every dialog has one is to own it.
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
 *
 * The scroll lock is the mouse-side equivalent: `<body>` is frozen for as long
 * as any dialog is open and restored to exactly what it was when the last one
 * closes ({@link lockBodyScroll}). Two caveats on this app specifically. Today
 * it is a no-op — `styles/index.css` already pins `body` to `overflow: hidden`
 * with `height: 100vh`, so there is nothing to freeze and no scrollbar gutter to
 * compensate for; the lock is here so that a change to that rule does not
 * silently reintroduce scroll-behind. And it locks the document, not the app's
 * inner `overflow-auto` panes — those are covered by the full-viewport wrapper,
 * which swallows the wheel event before it can reach them.
 */
export function Modal({
  label,
  labelledBy,
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

  // Freeze the page behind the dialog for as long as it is open. Mount-only for
  // the same reason as the focus effect: the lock belongs to the dialog's
  // lifetime, not to any prop.
  useEffect(() => {
    const body = document.body;
    const taken = lockBodyScroll(
      scrollLock,
      { overflow: body.style.overflow, paddingRight: body.style.paddingRight },
      window.innerWidth - document.documentElement.clientWidth,
      Number.parseFloat(getComputedStyle(body).paddingRight) || 0,
    );
    scrollLock = taken.state;
    if (taken.patch) {
      body.style.overflow = taken.patch.overflow;
      if (taken.patch.paddingRight !== null) body.style.paddingRight = taken.patch.paddingRight;
    }
    return () => {
      const released = unlockBodyScroll(scrollLock);
      scrollLock = released.state;
      if (released.restore) {
        body.style.overflow = released.restore.overflow;
        body.style.paddingRight = released.restore.paddingRight;
      }
    };
  }, []);

  const naming = modalNameAttrs(label, labelledBy);

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
        aria-label={naming.ariaLabel}
        aria-labelledby={naming.ariaLabelledBy}
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
