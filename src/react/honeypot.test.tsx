import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { HoneypotInputs, HoneypotProvider } from "../react.js";

describe(HoneypotInputs, () => {
  test("renders defaults without provider context", () => {
    const html = renderToStaticMarkup(<HoneypotInputs />);

    expect(html).toContain('id="name__confirm_wrap"');
    expect(html).toContain('name="name__confirm"');
    expect(html).toContain(".__honeypot_inputs { display: none; }");
    expect(html).not.toContain('name="from__confirm"');
  });

  test("renders the configured honeypot field names", () => {
    const html = renderToStaticMarkup(
      <HoneypotProvider
        encryptedValidFrom="signed-timestamp"
        nameFieldName="trap_field"
        validFromFieldName="trap_valid_from"
      >
        <HoneypotInputs />
      </HoneypotProvider>,
    );

    expect(html).toContain('name="trap_field"');
    expect(html).toContain('name="trap_valid_from"');
    expect(html).toContain('value="signed-timestamp"');
    expect(html).toContain("readOnly");
  });

  test("omits the signed timestamp input when validFromFieldName is null", () => {
    const html = renderToStaticMarkup(
      <HoneypotProvider
        encryptedValidFrom="signed-timestamp"
        nameFieldName="trap_field"
        validFromFieldName={null}
      >
        <HoneypotInputs />
      </HoneypotProvider>,
    );

    expect(html).toContain('name="trap_field"');
    expect(html).not.toContain('name="from__confirm"');
    expect(html).not.toContain("signed-timestamp");
  });

  test("omits the signed timestamp input when the encrypted value is missing", () => {
    const html = renderToStaticMarkup(
      <HoneypotProvider
        nameFieldName="trap_field"
        validFromFieldName="trap_valid_from"
      >
        <HoneypotInputs />
      </HoneypotProvider>,
    );

    expect(html).toContain('name="trap_field"');
    expect(html).not.toContain('name="trap_valid_from"');
  });

  test("uses the provided className and nonce", () => {
    const html = renderToStaticMarkup(
      <HoneypotInputs className="custom-honeypot" nonce="nonce-123" />,
    );

    expect(html).toContain('class="custom-honeypot"');
    expect(html).toContain('nonce="nonce-123"');
    expect(html).toContain(".custom-honeypot { display: none; }");
  });
});
