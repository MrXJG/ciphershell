# Design System: Linear Light + GM Security Accent

## 1. Visual Theme

This project uses a light developer-tool interface inspired by Linear's clean product surfaces, adapted for a GM/T SSH and SFTP client. The interface should feel calm, precise, and operational rather than decorative.

The base palette is cool light gray and white. Security-relevant affordances use a restrained teal accent, so connection, credential, and successful status states feel distinct without turning the whole product green.

## 2. Color Palette

### Core
- Canvas: `#F7F8FA` for the application background.
- Surface: `#FFFFFF` for cards, dialogs, panels, lists, tables, and inputs.
- Raised Surface: `#FAFBFC` for subtle nested surfaces.
- Ink: `#111318` for primary text.
- Body: `#374151` for normal readable text.
- Muted: `#6B7280` for secondary labels and helper text.
- Subtle: `#98A2B3` for disabled or low-emphasis text.
- Border: `#DDE2EA` for normal containment.
- Soft Border: `#E8ECF2` for low-emphasis separators.

### Accent
- Security Teal: `#0F766E` for primary connect actions, active secure states, and checked controls.
- Security Teal Hover: `#0B665F`.
- Focus Blue: `#2F6BFF` for focused fields and selected text where a conventional input focus color is clearer.
- Selection Blue: `#DDEBFF`.
- Warning: `#B45309`.
- Danger: `#B42318`.

## 3. Typography

Use a modern sans stack that works well across Windows, macOS, and Chinese UI. Put platform-native fonts first so packaged builds do not depend on unbundled design fonts:

`Segoe UI`, `Inter`, `PingFang SC`, `Microsoft YaHei UI`, `Microsoft YaHei`, `Noto Sans CJK SC`, `sans-serif`

Use `Cascadia Mono`, `Consolas`, `SF Mono`, `Menlo`, `Microsoft YaHei UI`, `monospace` for terminal and log text.

Rules:
- Prefer regular weight for body copy.
- Use medium weight only for buttons, headings, and selected emphasis.
- Keep labels compact and clear; avoid oversized marketing typography inside the desktop app.

## 4. Component Rules

### Main Window
- The app canvas is cool gray.
- Toolbar, side panel, terminal panel, SFTP panels, and dialogs are white surfaces with fine borders.
- Avoid heavy shadows; use borders and spacing for depth.

### Buttons
- Default buttons are white with gray borders.
- Hover state uses very light gray fill.
- Primary action buttons use Security Teal with white text.
- Disabled buttons must remain readable and visibly inactive.

### Inputs
- Inputs are white, rounded, and bordered.
- Focus state uses Focus Blue or Security Teal border depending on context.
- Placeholder text uses Subtle.

### Lists, Tables, Logs
- Lists and tables use white backgrounds and soft selection states.
- Logs should remain high contrast with monospaced text on a light surface.
- Newest SFTP logs stay at the top; the visual theme must not change log ordering behavior.

### Tabs
- Inactive tabs are pale gray.
- Active tabs are white with teal border emphasis.
- Keep only one close affordance on terminal tabs.

### Checkbox
- Checked state uses Security Teal fill and a white checkmark.
- The checkmark must remain visible on both normal and disabled checked states.

## 5. Layout Principles

- Use the existing Qt layout and behavior.
- Preserve SFTP, terminal, credential, and algorithm fallback flows.
- Favor compact operational density over marketing-style whitespace.
- Keep radius around 10-14px for cards and 16-20px for buttons.

## 6. Do / Don't

Do:
- Keep the UI light, crisp, and readable.
- Use teal only for security/action emphasis.
- Preserve the existing functional behavior while improving visual clarity.
- Verify with build and GUI tests after visual changes.

Don't:
- Reintroduce the previous warm dark brown theme.
- Use low-contrast gray text on gray backgrounds.
- Add decorative gradients, blur, or heavy shadows.
- Hide checkmarks, tab close controls, or status text through color choices.
