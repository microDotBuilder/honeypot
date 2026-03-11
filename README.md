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

## How It Works

The package has two pieces:

- `Honeypot` generates per-request input props and validates submitted `FormData`.
- `HoneypotProvider` and `HoneypotInputs` render the extra form controls needed in the browser.

This works well with TanStack Form because TanStack manages your real fields, while the honeypot renders additional DOM inputs inside the same native `<form>`. When the browser submits the form, all of those inputs end up in the same `FormData`.

## 1. Create the Honeypot on the Server

Create a single server-side `Honeypot` instance and keep the secret stable across requests and processes.

```ts
import { Honeypot } from "tanstack-utils/server";

export const honeypot = new Honeypot({
  randomizeNameFieldName: true,
  nameFieldName: "name__confirm",
  validFromFieldName: "from__confirm",
  encryptionSeed: process.env.HONEYPOT_SECRET!,
});
```

Recommended defaults:

- Keep `randomizeNameFieldName: true` for stronger bot resistance.
- Keep `validFromFieldName` enabled unless you have a compatibility reason to disable it.
- Treat `encryptionSeed` as required. It must be a stable secret string.

## 2. Create Honeypot Input Props Per Request

Get `honeypotInputProps` on the server for each request and pass them into your UI.

```ts
import { honeypot } from "./honeypot.server";

export async function loader() {
  return {
    honeypotInputProps: await honeypot.getInputProps(),
  };
}
```

`await honeypot.getInputProps()` returns:

```ts
type HoneypotInputProps = {
  nameFieldName: string;
  validFromFieldName: string | null;
  encryptedValidFrom: string;
};
```

`encryptedValidFrom` is an opaque signed validation token. When `randomizeNameFieldName` is enabled and `validFromFieldName` is present, the token also binds the generated honeypot field name to the submission.

## 3. Provide the Honeypot Props to the React Tree

Wrap the part of the UI that renders protected forms with `HoneypotProvider`.

```tsx
import type { Honeypot } from "tanstack-utils/server";
import { HoneypotProvider } from "tanstack-utils/react";

function App({
  honeypotInputProps,
  children,
}: {
  honeypotInputProps: Awaited<ReturnType<Honeypot["getInputProps"]>>;
  children: React.ReactNode;
}) {
  return (
    <HoneypotProvider {...honeypotInputProps}>
      {children}
    </HoneypotProvider>
  );
}
```

## 4. Render Honeypot Inputs Inside the Form

Render `HoneypotInputs` inside the same native `<form>` that the browser submits.

```tsx
import { HoneypotInputs } from "tanstack-utils/react";

function SomePublicForm() {
  return (
    <form method="post">
      <HoneypotInputs label="Please leave this field blank" />
      <button type="submit">Send</button>
    </form>
  );
}
```

## TanStack Form

TanStack Form works with this package today without a special adapter.

The important constraint is that the honeypot relies on real form controls and submitted `FormData`, not on TanStack field state alone.

Supported model:

1. TanStack Form manages your real inputs.
2. `HoneypotInputs` renders extra DOM inputs in the same `<form>`.
3. The browser submits one native `FormData`.
4. The server validates that `FormData` with `await honeypot.check(formData)`.

### TanStack Form Example

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
      password: "",
    },
  });

  return (
    <HoneypotProvider {...honeypotInputProps}>
      <form method="post" action="/signup">
        <HoneypotInputs />

        <form.Field name="email">
          {(field) => (
            <input
              name={field.name}
              value={field.state.value}
              onBlur={field.handleBlur}
              onChange={(event) => field.handleChange(event.target.value)}
            />
          )}
        </form.Field>

        <form.Field name="password">
          {(field) => (
            <input
              name={field.name}
              type="password"
              value={field.state.value}
              onBlur={field.handleBlur}
              onChange={(event) => field.handleChange(event.target.value)}
            />
          )}
        </form.Field>

        <button type="submit">Create account</button>
      </form>
    </HoneypotProvider>
  );
}
```

### Why This Works with TanStack Form

TanStack Form is managing your application fields like `email` and `password`, but the honeypot inputs do not need to live in TanStack state. They only need to exist as normal inputs in the submitted form.

As long as your TanStack-controlled inputs still render real form controls with `name={field.name}`, the browser will include both sets of fields in the same request payload.

## 5. Validate the Submitted FormData on the Server

Call `await honeypot.check(formData)` before normal validation or business logic.

```ts
import { SpamError } from "tanstack-utils/server";
import { honeypot } from "./honeypot.server";

export async function action({ request }: { request: Request }) {
  const formData = await request.formData();

  try {
    await honeypot.check(formData);
  } catch (error) {
    if (error instanceof SpamError) {
      return new Response("Spam detected", { status: 400 });
    }

    throw error;
  }

  const email = formData.get("email");
  const password = formData.get("password");

  return Response.json({ ok: true, email, password });
}
```

`honeypot.check(formData)` throws `SpamError` when:

- the trap field is filled
- the honeypot field is missing after the signed validation token is submitted
- the signed validation token is invalid
- the signed validation token is in the future

## Manual or JS-Only Submission

If you submit with TanStack Form state alone, the honeypot fields are not included automatically.

This will not work by itself:

```ts
const form = useForm({
  defaultValues: {
    email: "",
  },
  onSubmit: async ({ value }) => {
    await fetch("/signup", {
      method: "POST",
      body: JSON.stringify(value),
    });
  },
});
```

That payload only contains TanStack-managed state. It does not include the extra honeypot inputs rendered by `HoneypotInputs`.

If you need manual submission, build the request from the real form element so the browser includes the honeypot fields:

```tsx
function SignupFormWithManualSubmit() {
  return (
    <form
      method="post"
      onSubmit={async (event) => {
        event.preventDefault();

        const formData = new FormData(event.currentTarget);

        await fetch("/signup", {
          method: "POST",
          body: formData,
        });
      }}
    >
      <HoneypotInputs />
      <button type="submit">Send</button>
    </form>
  );
}
```

## Development

```bash
bun run build
bun test
```
