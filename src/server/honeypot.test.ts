import { createHmac } from "node:crypto";
import { describe, expect, test } from "bun:test";
import { encrypt } from "../common/crypto.js";
import { Honeypot, SpamError } from "./honeypot.js";

// biome-ignore lint/suspicious/noExplicitAny: Test
function invariant(condition: any, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

const ENCRYPTION_SEED = "TEST_HONEYPOT_SECRET";

function signTokenPayload(payload: string): string {
  const signature = createHmac("sha256", ENCRYPTION_SEED)
    .update(payload)
    .digest("base64url");

  return `${payload}.${signature}`;
}

describe(Honeypot, () => {
  test("generates input props", async () => {
    const props = await new Honeypot({
      encryptionSeed: ENCRYPTION_SEED,
    }).getInputProps();

    expect(props).toEqual({
      nameFieldName: "name__confirm",
      validFromFieldName: "from__confirm",
      encryptedValidFrom: expect.any(String),
    });
  });

  test("uses randomized nameFieldName", async () => {
    const honeypot = new Honeypot({
      encryptionSeed: ENCRYPTION_SEED,
      randomizeNameFieldName: true,
    });

    const props = await honeypot.getInputProps();

    expect(props.nameFieldName.startsWith("name__confirm_")).toBeTruthy();
  });

  test("uses randomized nameFieldName with prefix", async () => {
    const honeypot = new Honeypot({
      encryptionSeed: ENCRYPTION_SEED,
      randomizeNameFieldName: true,
      nameFieldName: "prefix",
    });

    const props = await honeypot.getInputProps();

    expect(props.nameFieldName.startsWith("prefix_")).toBeTruthy();
  });

  test("uses custom field names without randomization", async () => {
    const honeypot = new Honeypot({
      encryptionSeed: ENCRYPTION_SEED,
      nameFieldName: "company",
      validFromFieldName: "started_at",
    });

    const props = await honeypot.getInputProps();

    expect(props).toEqual({
      nameFieldName: "company",
      validFromFieldName: "started_at",
      encryptedValidFrom: expect.any(String),
    });
  });

  test("uses the provided validFromTimestamp", async () => {
    const timestamp = 1_700_000_000_000;
    const props = await new Honeypot({
      encryptionSeed: ENCRYPTION_SEED,
    }).getInputProps({
      validFromTimestamp: timestamp,
    });

    expect(props.encryptedValidFrom).toBe(
      await encrypt(timestamp.toString(), ENCRYPTION_SEED),
    );
  });

  test("checks validity on FormData", async () => {
    const formData = new FormData();

    await expect(
      new Honeypot({
        encryptionSeed: ENCRYPTION_SEED,
      }).check(formData),
    ).resolves.toBeUndefined();
  });

  test("does not block unrelated forms when no honeypot fields are submitted", async () => {
    const formData = new FormData();
    formData.set("email", "dev@example.com");
    formData.set("message", "Hello");

    await expect(
      new Honeypot({
        encryptionSeed: ENCRYPTION_SEED,
      }).check(formData),
    ).resolves.toBeUndefined();
  });

  test(
    "checks validity of FormData with a signed validation token and randomized " +
      "field name",
    async () => {
      const honeypot = new Honeypot({
        encryptionSeed: ENCRYPTION_SEED,
        randomizeNameFieldName: true,
      });

      const props = await honeypot.getInputProps();
      invariant(props.validFromFieldName, "validFromFieldName is null");

      const formData = new FormData();
      formData.set(props.nameFieldName, "");
      formData.set(props.validFromFieldName, props.encryptedValidFrom);

      await expect(honeypot.check(formData)).resolves.toBeUndefined();
    },
  );

  test("accepts legacy timestamp tokens for randomized field names", async () => {
    const honeypot = new Honeypot({
      encryptionSeed: ENCRYPTION_SEED,
      randomizeNameFieldName: true,
    });

    const props = await honeypot.getInputProps({
      validFromTimestamp: 1_700_000_000_000,
    });
    invariant(props.validFromFieldName, "validFromFieldName is null");

    const formData = new FormData();
    formData.set(props.nameFieldName, "");
    formData.set(
      props.validFromFieldName,
      await encrypt("1700000000000", ENCRYPTION_SEED),
    );

    await expect(honeypot.check(formData)).resolves.toBeUndefined();
  });

  test("fails validity check if input is not present", async () => {
    const honeypot = new Honeypot({
      encryptionSeed: ENCRYPTION_SEED,
    });

    const props = await honeypot.getInputProps();
    invariant(props.validFromFieldName, "validFromFieldName is null");

    const formData = new FormData();
    formData.set(props.validFromFieldName, props.encryptedValidFrom);

    await expect(honeypot.check(formData)).rejects.toThrowError(
      new SpamError("Missing honeypot input"),
    );
  });

  test("fails validity check if input is not empty", async () => {
    const honeypot = new Honeypot({
      encryptionSeed: ENCRYPTION_SEED,
    });

    const props = await honeypot.getInputProps();

    const formData = new FormData();
    formData.set(props.nameFieldName, "not empty");

    await expect(honeypot.check(formData)).rejects.toThrowError(
      new SpamError("Honeypot input not empty"),
    );
  });

  test("fails validity check if honeypot input is a file", async () => {
    const honeypot = new Honeypot({
      encryptionSeed: ENCRYPTION_SEED,
    });

    const props = await honeypot.getInputProps();

    const formData = new FormData();
    formData.set(props.nameFieldName, new File(["bot"], "bot.txt"));

    await expect(honeypot.check(formData)).rejects.toThrowError(
      new SpamError("Invalid honeypot input"),
    );
  });

  test("fails if valid from timestamp is missing", async () => {
    const honeypot = new Honeypot({
      encryptionSeed: ENCRYPTION_SEED,
    });

    const props = await honeypot.getInputProps();

    const formData = new FormData();
    formData.set(props.nameFieldName, "");

    await expect(honeypot.check(formData)).rejects.toThrowError(
      new SpamError("Missing honeypot valid from input"),
    );
  });

  test("fails if the valid from token is missing the payload", async () => {
    const honeypot = new Honeypot({
      encryptionSeed: ENCRYPTION_SEED,
    });

    const props = await honeypot.getInputProps();
    invariant(props.validFromFieldName, "validFromFieldName is null");

    const formData = new FormData();
    formData.set(props.nameFieldName, "");
    formData.set(props.validFromFieldName, ".signature");

    await expect(honeypot.check(formData)).rejects.toThrowError(
      new SpamError("Invalid honeypot valid from input"),
    );
  });

  test("fails if the valid from token is missing the signature", async () => {
    const honeypot = new Honeypot({
      encryptionSeed: ENCRYPTION_SEED,
    });

    const props = await honeypot.getInputProps();
    invariant(props.validFromFieldName, "validFromFieldName is null");

    const formData = new FormData();
    formData.set(props.nameFieldName, "");
    formData.set(props.validFromFieldName, "payload.");

    await expect(honeypot.check(formData)).rejects.toThrowError(
      new SpamError("Invalid honeypot valid from input"),
    );
  });

  test("fails if the timestamp is not valid", async () => {
    const honeypot = new Honeypot({
      encryptionSeed: ENCRYPTION_SEED,
    });

    const props = await honeypot.getInputProps();
    invariant(props.validFromFieldName, "validFromFieldName is null");

    const formData = new FormData();
    formData.set(props.nameFieldName, "");
    formData.set(
      props.validFromFieldName,
      await encrypt("invalid", ENCRYPTION_SEED),
    );

    await expect(honeypot.check(formData)).rejects.toThrowError(
      new SpamError("Invalid honeypot valid from input"),
    );
  });

  test("fails if the valid from payload is malformed base64url", async () => {
    const honeypot = new Honeypot({
      encryptionSeed: ENCRYPTION_SEED,
    });

    const props = await honeypot.getInputProps();
    invariant(props.validFromFieldName, "validFromFieldName is null");

    const formData = new FormData();
    formData.set(props.nameFieldName, "");
    formData.set(props.validFromFieldName, signTokenPayload("***"));

    await expect(honeypot.check(formData)).rejects.toThrowError(
      new SpamError("Invalid honeypot valid from input"),
    );
  });

  test("fails if the valid from input is a file", async () => {
    const honeypot = new Honeypot({
      encryptionSeed: ENCRYPTION_SEED,
    });

    const props = await honeypot.getInputProps();
    invariant(props.validFromFieldName, "validFromFieldName is null");

    const formData = new FormData();
    formData.set(props.nameFieldName, "");
    formData.set(
      props.validFromFieldName,
      new File(["bot"], "bot.txt"),
    );

    await expect(honeypot.check(formData)).rejects.toThrowError(
      new SpamError("Missing honeypot valid from input"),
    );
  });

  test("fails if valid from input is duplicated", async () => {
    const honeypot = new Honeypot({
      encryptionSeed: ENCRYPTION_SEED,
    });

    const props = await honeypot.getInputProps();
    invariant(props.validFromFieldName, "validFromFieldName is null");

    const formData = new FormData();
    formData.set(props.nameFieldName, "");
    formData.append(props.validFromFieldName, props.encryptedValidFrom);
    formData.append(
      props.validFromFieldName,
      await encrypt(Date.now().toString(), ENCRYPTION_SEED),
    );

    await expect(honeypot.check(formData)).rejects.toThrowError(
      new SpamError("Invalid honeypot valid from input"),
    );
  });

  test("fails if valid from input has multiple values and one is a file", async () => {
    const honeypot = new Honeypot({
      encryptionSeed: ENCRYPTION_SEED,
    });

    const props = await honeypot.getInputProps();
    invariant(props.validFromFieldName, "validFromFieldName is null");

    const formData = new FormData();
    formData.set(props.nameFieldName, "");
    formData.append(props.validFromFieldName, props.encryptedValidFrom);
    formData.append(props.validFromFieldName, new File(["bot"], "bot.txt"));

    await expect(honeypot.check(formData)).rejects.toThrowError(
      new SpamError("Invalid honeypot valid from input"),
    );
  });

  test("fails if the valid from signature is tampered with", async () => {
    const honeypot = new Honeypot({
      encryptionSeed: ENCRYPTION_SEED,
    });

    const props = await honeypot.getInputProps();
    invariant(props.validFromFieldName, "validFromFieldName is null");

    const formData = new FormData();
    formData.set(props.nameFieldName, "");
    formData.set(
      props.validFromFieldName,
      `${props.encryptedValidFrom}x`,
    );

    await expect(honeypot.check(formData)).rejects.toThrowError(
      new SpamError("Invalid honeypot valid from input"),
    );
  });

  test("fails if the valid from signature was encrypted with another seed", async () => {
    const honeypot = new Honeypot({
      encryptionSeed: ENCRYPTION_SEED,
    });

    const props = await honeypot.getInputProps();
    invariant(props.validFromFieldName, "validFromFieldName is null");

    const formData = new FormData();
    formData.set(props.nameFieldName, "");
    formData.set(
      props.validFromFieldName,
      await encrypt(Date.now().toString(), "ANOTHER_SECRET"),
    );

    await expect(honeypot.check(formData)).rejects.toThrowError(
      new SpamError("Invalid honeypot valid from input"),
    );
  });

  test("fails if valid from timestamp is in the future", async () => {
    const honeypot = new Honeypot({
      encryptionSeed: ENCRYPTION_SEED,
    });

    const props = await honeypot.getInputProps();
    invariant(props.validFromFieldName, "validFromFieldName is null");

    const formData = new FormData();
    formData.set(props.nameFieldName, "");
    formData.set(
      props.validFromFieldName,
      await encrypt((Date.now() + 10_000).toString(), ENCRYPTION_SEED),
    );

    await expect(honeypot.check(formData)).rejects.toThrowError(
      new SpamError("Honeypot valid from is in future"),
    );
  });

  test("accepts custom field names during validation", async () => {
    const honeypot = new Honeypot({
      encryptionSeed: ENCRYPTION_SEED,
      nameFieldName: "company",
      validFromFieldName: "started_at",
    });

    const props = await honeypot.getInputProps();
    invariant(props.validFromFieldName, "validFromFieldName is null");

    const formData = new FormData();
    formData.set("company", "");
    formData.set("started_at", props.encryptedValidFrom);

    await expect(honeypot.check(formData)).resolves.toBeUndefined();
  });

  test.each([
    "0",
    "-1",
    "Infinity",
    String(Number.MAX_SAFE_INTEGER),
  ])(
    "fails if valid from timestamp is outside accepted bounds: %s",
    async (value) => {
      const honeypot = new Honeypot({
        encryptionSeed: ENCRYPTION_SEED,
      });

      const props = await honeypot.getInputProps();
      invariant(props.validFromFieldName, "validFromFieldName is null");

      const formData = new FormData();
      formData.set(props.nameFieldName, "");
      formData.set(
        props.validFromFieldName,
        await encrypt(value, ENCRYPTION_SEED),
      );

      await expect(honeypot.check(formData)).rejects.toThrowError(
        new SpamError("Invalid honeypot valid from input"),
      );
    },
  );

  test("does not check for valid from timestamp if it's set to null", async () => {
    const honeypot = new Honeypot({
      encryptionSeed: ENCRYPTION_SEED,
      validFromFieldName: null,
    });

    const props = await honeypot.getInputProps();

    expect(props.validFromFieldName).toBeNull();

    const formData = new FormData();
    formData.set(props.nameFieldName, "");

    await expect(honeypot.check(formData)).resolves.toBeUndefined();
  });

  test(
    "rejects valid from tokens with extra separators",
    async () => {
      const honeypot = new Honeypot({
        encryptionSeed: ENCRYPTION_SEED,
      });

      const props = await honeypot.getInputProps();
      invariant(props.validFromFieldName, "validFromFieldName is null");

      const formData = new FormData();
      formData.set(props.nameFieldName, "");
      formData.set(
        props.validFromFieldName,
        `${props.encryptedValidFrom}.extra`,
      );

      await expect(honeypot.check(formData)).rejects.toThrowError(
        new SpamError("Invalid honeypot valid from input"),
      );
    },
  );

  test(
    "rejects spoofed randomized field prefixes",
    async () => {
      const honeypot = new Honeypot({
        encryptionSeed: ENCRYPTION_SEED,
        randomizeNameFieldName: true,
      });

      const props = await honeypot.getInputProps();
      invariant(props.validFromFieldName, "validFromFieldName is null");

      const formData = new FormData();
      formData.set("name__confirm_spoofed", "");
      formData.set(props.validFromFieldName, props.encryptedValidFrom);

      await expect(honeypot.check(formData)).rejects.toThrowError(
        new SpamError("Missing honeypot input"),
      );
    },
  );

  test(
    "rejects duplicate honeypot values when any value is filled",
    async () => {
      const honeypot = new Honeypot({
        encryptionSeed: ENCRYPTION_SEED,
      });

      const props = await honeypot.getInputProps();
      invariant(props.validFromFieldName, "validFromFieldName is null");

      const formData = new FormData();
      formData.append(props.nameFieldName, "");
      formData.append(props.nameFieldName, "bot-value");
      formData.set(props.validFromFieldName, props.encryptedValidFrom);

      await expect(honeypot.check(formData)).rejects.toThrowError(
        new SpamError("Honeypot input not empty"),
      );
    },
  );
});
