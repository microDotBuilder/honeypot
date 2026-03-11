# Honeypot

Reusable server-side honeypot protection with a small React adapter.

## Install

```bash
bun install
```

Build the publishable package artifacts:

```bash
bun run build
```

## Public API

```ts
import { Honeypot, SpamError } from "tanstack-utils/server";
import { HoneypotInputs, HoneypotProvider } from "tanstack-utils/react";
```

The package also re-exports everything from the root entrypoint:

```ts
import {
  Honeypot,
  SpamError,
  HoneypotInputs,
  HoneypotProvider,
} from "tanstack-utils";
```

## Server Usage

```ts
import { Honeypot } from "tanstack-utils/server";

export const honeypot = new Honeypot({
  encryptionSeed: process.env.HONEYPOT_SECRET!,
  randomizeNameFieldName: true,
});
```

Before you process a form submission:

```ts
const formData = await request.formData();
await honeypot.check(formData);
```

`honeypot.check(formData)` throws `SpamError` when the trap field is filled, the honeypot field is missing after the signed validation token is submitted, or the signed validation token is invalid.

## React Usage

Create honeypot props on the server and pass them into `HoneypotProvider`. Render `HoneypotInputs` inside the same `<form>` so both hidden inputs are included in the browser `FormData`.

`encryptedValidFrom` should be treated as an opaque signed validation token. When `randomizeNameFieldName` is enabled and `validFromFieldName` is present, the token also binds the exact generated honeypot field name to the submission. If `validFromFieldName` is `null`, the package preserves the legacy behavior and cannot verify the exact randomized field name on the server.

```tsx
import type { Honeypot } from "tanstack-utils/server";
import { HoneypotInputs, HoneypotProvider } from "tanstack-utils/react";

function ContactForm({
  honeypotInputProps,
}: {
  honeypotInputProps: Awaited<ReturnType<Honeypot["getInputProps"]>>;
}) {
  return (
    <HoneypotProvider {...honeypotInputProps}>
      <form method="post">
        <HoneypotInputs />
        <button type="submit">Send</button>
      </form>
    </HoneypotProvider>
  );
}
```

## TanStack Form

TanStack Form works with this honeypot as long as you use a real HTML form submission.

Compatibility note: TanStack Form is supported through native browser `FormData` submission, not a TanStack-specific adapter.

Supported flow:

1. Create honeypot input props on the server with `await honeypot.getInputProps()`.
2. Render `<HoneypotInputs />` inside the same native `<form method="post">`.
3. Keep TanStack field inputs as real form controls with `name={field.name}`.
4. On the server, call `await honeypot.check(formData)` before your regular validation.

Example:

```tsx
import { useForm } from "@tanstack/react-form";
import type { Honeypot } from "tanstack-utils/server";
import { HoneypotInputs, HoneypotProvider } from "tanstack-utils/react";

function SignupForm({
  honeypotInputProps,
}: {
  honeypotInputProps: Awaited<ReturnType<Honeypot["getInputProps"]>>;
}) {
  const form = useForm({
    defaultValues: {
      email: "",
    },
  });

  return (
    <HoneypotProvider {...honeypotInputProps}>
      <form method="post">
        <HoneypotInputs />

        <form.Field name="email">
          {(field) => (
            <input
              name={field.name}
              onBlur={field.handleBlur}
              onChange={(event) => field.handleChange(event.target.value)}
              value={field.state.value}
            />
          )}
        </form.Field>

        <button type="submit">Create account</button>
      </form>
    </HoneypotProvider>
  );
}
```

Out of scope for this package:

- JS-only mutation submissions that do not send the native form `FormData`
- TanStack-specific hooks or adapters

If you bypass native form submission and build the request body yourself, you must manually include the honeypot field and signed `validFrom` token in that payload.

## Development

```bash
bun run build
bun test
```
