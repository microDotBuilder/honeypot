import * as React from "react";
import type { HoneypotInputProps } from "../server/honeypot.js";

type HoneypotContextType = Partial<HoneypotInputProps>;

const HoneypotContext = React.createContext<HoneypotContextType>({});

export function HoneypotInputs({
  label = "Please leave this field blank",
  nonce,
  className = "__honeypot_inputs",
}: HoneypotInputs.Props) {
  const context = React.useContext(HoneypotContext);

  const {
    nameFieldName = "name__confirm",
    validFromFieldName = "from__confirm",
    encryptedValidFrom,
  } = context;

  return (
    <div
      aria-hidden="true"
      className={className}
      id={`${nameFieldName}_wrap`}
    >
      <style nonce={nonce}>{`.${className} { display: none; }`}</style>

      <label htmlFor={nameFieldName}>{label}</label>
      <input
        autoComplete="nope"
        defaultValue=""
        id={nameFieldName}
        name={nameFieldName}
        tabIndex={-1}
        type="text"
      />

      {validFromFieldName && encryptedValidFrom ? (
        <>
          <label htmlFor={validFromFieldName}>{label}</label>
          <input
            autoComplete="off"
            id={validFromFieldName}
            name={validFromFieldName}
            readOnly
            tabIndex={-1}
            type="text"
            value={encryptedValidFrom}
          />
        </>
      ) : null}
    </div>
  );
}

export namespace HoneypotInputs {
  export type Props = {
    label?: string;
    nonce?: string;
    /**
     * The classname used to link the Honeypot input with the CSS that hides it.
     * @default "__honeypot_inputs"
     */
    className?: string;
  };
}

export type HoneypotProviderProps = HoneypotContextType & {
  children: React.ReactNode;
};

export function HoneypotProvider({
  children,
  ...context
}: HoneypotProviderProps) {
  return (
    <HoneypotContext.Provider value={context}>
      {children}
    </HoneypotContext.Provider>
  );
}
