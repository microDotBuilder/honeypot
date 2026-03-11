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
   * The signed value of the current timestamp.
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
   * The secret used to sign the valid from timestamp.
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

    return {
      nameFieldName: this.createNameFieldName(),
      validFromFieldName: this.validFromFieldName,
      encryptedValidFrom: await this.encrypt(validFromTimestamp.toString()),
    };
  }

  public async check(formData: FormData): Promise<void> {
    let nameFieldName = this.baseNameFieldName;

    if (this.config.randomizeNameFieldName) {
      const actualName = this.getRandomizedNameFieldName(
        nameFieldName,
        formData,
      );

      if (actualName) {
        nameFieldName = actualName;
      }
    }

    if (!this.shouldCheckHoneypot(formData, nameFieldName)) {
      return;
    }

    if (!formData.has(nameFieldName)) {
      throw new SpamError("Missing honeypot input");
    }

    const honeypotValue = formData.get(nameFieldName);

    if (typeof honeypotValue !== "string") {
      throw new SpamError("Invalid honeypot input");
    }

    if (honeypotValue !== "") {
      throw new SpamError("Honeypot input not empty");
    }

    if (!this.validFromFieldName) {
      return;
    }

    const validFrom = formData.get(this.validFromFieldName);

    if (typeof validFrom !== "string" || validFrom.length === 0) {
      throw new SpamError("Missing honeypot valid from input");
    }

    const time = await this.decrypt(validFrom);

    if (!time) {
      throw new SpamError("Invalid honeypot valid from input");
    }

    const timestamp = Number(time);

    if (!this.isValidTimeStamp(timestamp)) {
      throw new SpamError("Invalid honeypot valid from input");
    }

    if (this.isFuture(timestamp)) {
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
  ): boolean {
    return (
      formData.has(nameFieldName) ||
      Boolean(
        this.validFromFieldName && formData.has(this.validFromFieldName),
      ) ||
      Boolean(
        this.config.randomizeNameFieldName &&
        this.getRandomizedNameFieldName(nameFieldName, formData),
      )
    );
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

  protected isValidTimeStamp(timestamp: number): boolean {
    if (Number.isNaN(timestamp)) return false;
    if (!Number.isFinite(timestamp)) return false;
    if (timestamp <= 0) return false;
    if (timestamp >= Number.MAX_SAFE_INTEGER) return false;
    return true;
  }
}
