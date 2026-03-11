import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { HoneypotInputs, HoneypotProvider } from "./react.js";
import { Honeypot, SpamError } from "./server.js";

const ENCRYPTION_SEED = "TEST_HONEYPOT_SECRET";

function getInputTag(html: string, fieldName: string): string {
  const escapedFieldName = fieldName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = html.match(
    new RegExp(`<input[^>]*name="${escapedFieldName}"[^>]*>`, "i"),
  );

  if (!match) {
    throw new Error(`Missing input for ${fieldName}`);
  }

  return match[0];
}

function getInputValue(inputTag: string): string | null {
  const match = inputTag.match(/value="([^"]*)"/i);
  return match?.[1] ?? null;
}

describe("React and server integration", () => {
  test("accepts a rendered honeypot form submission", async () => {
    const honeypot = new Honeypot({
      encryptionSeed: ENCRYPTION_SEED,
    });
    const inputProps = await honeypot.getInputProps();
    const html = renderToStaticMarkup(
      <HoneypotProvider {...inputProps}>
        <form method="post">
          <HoneypotInputs />
          <input name="email" value="dev@example.com" readOnly />
        </form>
      </HoneypotProvider>,
    );

    const honeypotTag = getInputTag(html, inputProps.nameFieldName);
    const validFromTag = getInputTag(
      html,
      inputProps.validFromFieldName ?? "from__confirm",
    );
    const validFromValue = getInputValue(validFromTag);

    expect(honeypotTag).toContain(`name="${inputProps.nameFieldName}"`);
    expect(validFromValue).toBe(inputProps.encryptedValidFrom);

    const formData = new FormData();
    formData.set(inputProps.nameFieldName, "");
    formData.set("email", "dev@example.com");

    if (!inputProps.validFromFieldName || !validFromValue) {
      throw new Error("Expected a valid from field in integration test");
    }

    formData.set(inputProps.validFromFieldName, validFromValue);

    await expect(honeypot.check(formData)).resolves.toBeUndefined();
  });

  test("rejects a rendered honeypot form submission when the trap field is filled", async () => {
    const honeypot = new Honeypot({
      encryptionSeed: ENCRYPTION_SEED,
    });
    const inputProps = await honeypot.getInputProps();
    const html = renderToStaticMarkup(
      <HoneypotProvider {...inputProps}>
        <form method="post">
          <HoneypotInputs />
        </form>
      </HoneypotProvider>,
    );

    const validFromTag = getInputTag(
      html,
      inputProps.validFromFieldName ?? "from__confirm",
    );
    const validFromValue = getInputValue(validFromTag);

    if (!inputProps.validFromFieldName || !validFromValue) {
      throw new Error("Expected a valid from field in integration test");
    }

    const formData = new FormData();
    formData.set(inputProps.nameFieldName, "bot-value");
    formData.set(inputProps.validFromFieldName, validFromValue);

    await expect(honeypot.check(formData)).rejects.toThrowError(
      new SpamError("Honeypot input not empty"),
    );
  });

  test("accepts randomized honeypot field names after a render round-trip", async () => {
    const honeypot = new Honeypot({
      encryptionSeed: ENCRYPTION_SEED,
      randomizeNameFieldName: true,
    });
    const inputProps = await honeypot.getInputProps();
    const html = renderToStaticMarkup(
      <HoneypotProvider {...inputProps}>
        <form method="post">
          <HoneypotInputs />
        </form>
      </HoneypotProvider>,
    );

    const randomizedFieldNameMatch = html.match(/name="(name__confirm_[^"]+)"/);

    if (!randomizedFieldNameMatch) {
      throw new Error("Missing randomized honeypot field in rendered HTML");
    }

    const randomizedFieldName = randomizedFieldNameMatch[1];

    if (!randomizedFieldName) {
      throw new Error("Missing randomized honeypot field name");
    }
    const validFromTag = getInputTag(
      html,
      inputProps.validFromFieldName ?? "from__confirm",
    );
    const validFromValue = getInputValue(validFromTag);

    if (!inputProps.validFromFieldName || !validFromValue) {
      throw new Error("Expected a valid from field in integration test");
    }

    const formData = new FormData();
    formData.set(randomizedFieldName, "");
    formData.set(inputProps.validFromFieldName, validFromValue);

    await expect(honeypot.check(formData)).resolves.toBeUndefined();
  });
});
