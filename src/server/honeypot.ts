import { decrypt, encrypt, randomString } from "../common/crypto.js";

export interface HoneypotInputProps {
  /**
   * The name expected to be used by the honeypot input field.
   */
  nameFieldName: string;
  /**
   * The name expected to be used by the honeypot valid from input field.
   */
  validFromFieldName: string | null;
  /**
   * An opaque signed validation token for the current request.
   */
  encryptedValidFrom: string;
}

export interface HoneypotConfig {
  /**
   * Enable randomization of the name field name, this way the honeypot field
   * name will be different for each request.
   */
  randomizeNameFieldName?: boolean;
  /**
   * The name of the field that will be used for the honeypot input.
   */
  nameFieldName?: string;
  /**
   * The name of the field that will be used for the honeypot valid from input.
   */
  validFromFieldName?: string | null;
  /**
   * The secret used to sign the honeypot validation token.
   * This must be stable across requests.
   */
  encryptionSeed: string;
}

export interface GetInputPropsOptions {
  /**
   * Since when the timestamp is valid.
   */
  validFromTimestamp?: number;
}

export class SpamError extends Error {
  override readonly name = "SpamError";
}

const DEFAULT_NAME_FIELD_NAME = "name__confirm";
const DEFAULT_VALID_FROM_FIELD_NAME = "from__confirm";

type HoneypotValidationToken =
  | {
      validFromTimestamp: number;
      nameFieldName?: undefined;
    }
  | {
      validFromTimestamp: number;
      nameFieldName: string;
    };

/**
 * Module used to implement a Honeypot.
 * A Honeypot is a visually hidden input that is used to detect spam bots. This
 * field is expected to be left empty by users because they don't see it, but
 * bots will fill it falling in the honeypot trap.
 */
export class Honeypot {
  protected config: HoneypotConfig;

  constructor(config: HoneypotConfig) {
    this.config = config;
  }

  /**
   * Get the HoneypotInputProps to be used in your forms.
   */
  public async getInputProps(
    options: GetInputPropsOptions = {},
  ): Promise<HoneypotInputProps> {
    const validFromTimestamp = options.validFromTimestamp ?? Date.now();
    const nameFieldName = this.createNameFieldName();

    return {
      nameFieldName,
      validFromFieldName: this.validFromFieldName,
      encryptedValidFrom: await this.createValidationToken(
        validFromTimestamp,
        nameFieldName,
      ),
    };
  }

  public async check(formData: FormData): Promise<void> {
    const validationToken = await this.getValidationToken(formData);
    const submittedRandomizedNameFieldName = this.config.randomizeNameFieldName
      ? this.getRandomizedNameFieldName(this.baseNameFieldName, formData)
      : undefined;

    const nameFieldName =
      validationToken?.nameFieldName ??
      submittedRandomizedNameFieldName ??
      this.baseNameFieldName;

    if (
      !this.shouldCheckHoneypot(
        formData,
        nameFieldName,
        Boolean(validationToken),
        submittedRandomizedNameFieldName,
      )
    ) {
      return;
    }

    this.checkHoneypotInput(formData, nameFieldName);

    if (!this.validFromFieldName) {
      return;
    }

    if (!validationToken) {
      throw new SpamError("Missing honeypot valid from input");
    }

    if (this.isFuture(validationToken.validFromTimestamp)) {
      throw new SpamError("Honeypot valid from is in future");
    }
  }

  protected get baseNameFieldName(): string {
    return this.config.nameFieldName ?? DEFAULT_NAME_FIELD_NAME;
  }

  protected get validFromFieldName(): string | null {
    if (this.config.validFromFieldName === undefined) {
      return DEFAULT_VALID_FROM_FIELD_NAME;
    }

    return this.config.validFromFieldName;
  }

  protected get encryptionSeed(): string {
    return this.config.encryptionSeed;
  }

  protected createNameFieldName(): string {
    const fieldName = this.baseNameFieldName;

    if (!this.config.randomizeNameFieldName) {
      return fieldName;
    }

    return `${fieldName}_${this.randomValue()}`;
  }

  protected async createValidationToken(
    validFromTimestamp: number,
    nameFieldName: string,
  ): Promise<string> {
    if (!this.shouldBindRandomizedNameField()) {
      return this.encrypt(validFromTimestamp.toString());
    }

    return this.encrypt(
      JSON.stringify({
        validFromTimestamp,
        nameFieldName,
      }),
    );
  }

  protected shouldBindRandomizedNameField(): boolean {
    return Boolean(this.config.randomizeNameFieldName && this.validFromFieldName);
  }

  protected getRandomizedNameFieldName(
    nameFieldName: string,
    formData: FormData,
  ): string | undefined {
    for (const key of formData.keys()) {
      if (key === nameFieldName) {
        return key;
      }

      if (key.startsWith(`${nameFieldName}_`)) {
        return key;
      }
    }

    return undefined;
  }

  protected shouldCheckHoneypot(
    formData: FormData,
    nameFieldName: string,
    hasValidationToken: boolean,
    submittedRandomizedNameFieldName?: string,
  ): boolean {
    return (
      hasValidationToken ||
      formData.has(nameFieldName) ||
      Boolean(submittedRandomizedNameFieldName)
    );
  }

  protected checkHoneypotInput(formData: FormData, nameFieldName: string): void {
    if (!formData.has(nameFieldName)) {
      throw new SpamError("Missing honeypot input");
    }

    const honeypotValues = formData.getAll(nameFieldName);

    for (const honeypotValue of honeypotValues) {
      if (typeof honeypotValue !== "string") {
        throw new SpamError("Invalid honeypot input");
      }

      if (honeypotValue !== "") {
        throw new SpamError("Honeypot input not empty");
      }
    }
  }

  protected async getValidationToken(
    formData: FormData,
  ): Promise<HoneypotValidationToken | null> {
    if (!this.validFromFieldName) {
      return null;
    }

    const validFromValues = formData.getAll(this.validFromFieldName);

    if (validFromValues.length === 0) {
      return null;
    }

    if (validFromValues.length !== 1) {
      throw new SpamError("Invalid honeypot valid from input");
    }

    const [validFrom] = validFromValues;

    if (typeof validFrom !== "string" || validFrom.length === 0) {
      throw new SpamError("Missing honeypot valid from input");
    }

    const decryptedToken = await this.decrypt(validFrom);

    if (!decryptedToken) {
      throw new SpamError("Invalid honeypot valid from input");
    }

    const validationToken = this.parseValidationToken(decryptedToken);

    if (!validationToken) {
      throw new SpamError("Invalid honeypot valid from input");
    }

    return validationToken;
  }

  protected parseValidationToken(
    value: string,
  ): HoneypotValidationToken | null {
    if (!value.startsWith("{")) {
      return this.parseLegacyValidationToken(value);
    }

    let parsedValue: unknown;

    try {
      parsedValue = JSON.parse(value);
    } catch {
      return null;
    }

    if (!parsedValue || typeof parsedValue !== "object") {
      return null;
    }

    const validFromTimestamp = Reflect.get(parsedValue, "validFromTimestamp");
    const nameFieldName = Reflect.get(parsedValue, "nameFieldName");

    if (!this.isValidTimeStamp(validFromTimestamp)) {
      return null;
    }

    if (typeof nameFieldName !== "string" || nameFieldName.length === 0) {
      return null;
    }

    return {
      validFromTimestamp,
      nameFieldName,
    };
  }

  protected parseLegacyValidationToken(
    value: string,
  ): HoneypotValidationToken | null {
    const validFromTimestamp = Number(value);

    if (!this.isValidTimeStamp(validFromTimestamp)) {
      return null;
    }

    return {
      validFromTimestamp,
    };
  }

  protected randomValue(): string {
    return randomString();
  }

  protected encrypt(value: string): Promise<string> {
    return encrypt(value, this.encryptionSeed);
  }

  protected decrypt(value: string): Promise<string | null> {
    return decrypt(value, this.encryptionSeed);
  }

  protected isFuture(timestamp: number): boolean {
    return timestamp > Date.now();
  }

  protected isValidTimeStamp(timestamp: unknown): timestamp is number {
    if (typeof timestamp !== "number") return false;
    if (Number.isNaN(timestamp)) return false;
    if (!Number.isFinite(timestamp)) return false;
    if (timestamp <= 0) return false;
    if (timestamp >= Number.MAX_SAFE_INTEGER) return false;
    return true;
  }
}
