import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,
  {
    // The React Compiler lint rules (eslint-plugin-react-hooks v7) are new and,
    // here, flag idiomatic patterns rather than real bugs: resetting loading/error
    // synchronously at the start of a data-fetching effect (set-state-in-effect),
    // and the intentional Math.random() skeleton width in the generated shadcn/ui
    // sidebar (purity). Keep them as warnings so the signal survives without
    // breaking the build.
    rules: {
      "react-hooks/set-state-in-effect": "warn",
      "react-hooks/purity": "warn",
    },
  },
  // Override default ignores of eslint-config-next.
  globalIgnores([
    // Default ignores of eslint-config-next:
    ".next/**",
    "out/**",
    "build/**",
    "next-env.d.ts",
  ]),
]);

export default eslintConfig;
