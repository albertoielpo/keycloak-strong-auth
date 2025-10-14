module.exports = {
    parser: "@typescript-eslint/parser",
    parserOptions: {
        project: "tsconfig.json",
        tsconfigRootDir: __dirname,
        sourceType: "module",
        warnOnUnsupportedTypeScriptVersion: false
    },
    plugins: ["@typescript-eslint/eslint-plugin"],
    extends: [
        "airbnb-base",
        "airbnb-typescript/base",
        "plugin:prettier/recommended"
    ],
    root: true,
    env: {
        node: true,
        jest: true
    },
    ignorePatterns: [".eslintrc.js", "src/**/*.spec.ts"],
    overrides: [
        {
            /**
             * Set as warn in order to allow schema files to have multiple class definitions in case of nested schemas
             */
            files: [
                "src/**/*.schema.ts",
                "src/**/*.entity.ts",
                "src/**/*.enum.ts"
            ],
            rules: {
                "max-classes-per-file": "off",
                "import/prefer-default-export": "off"
            }
        },
        {
            /**
             * Permits console.log in main.ts and app.module.ts files
             */
            files: ["src/main.ts", "src/**/app.module.ts"],
            rules: {
                "no-console": "off"
            }
        },
        {
            /**
             * Permits to omit return type in decorator files
             */
            files: ["src/**/*.decorator.ts", "src/**/*.module.ts"],
            rules: {
                "@typescript-eslint/explicit-function-return-type": "off",
                "@typescript-eslint/explicit-module-boundary-types": "off",
                "class-methods-use-this": "off"
            }
        }
    ],
    rules: {
        "new-cap": "off",
        "no-console": "error",
        "no-await-in-loop": "warn",
        "no-plusplus": "off",
        "@typescript-eslint/explicit-function-return-type": "error",
        "@typescript-eslint/explicit-module-boundary-types": "error",
        "@typescript-eslint/lines-between-class-members": "off",
        "no-underscore-dangle": "off",
        "no-restricted-syntax": ["error", "LabeledStatement", "WithStatement"],
        "guard-for-in": "off",
        "@typescript-eslint/no-explicit-any": "error",
        "no-continue": "off",
        "class-methods-use-this": "warn",
        "@typescript-eslint/no-floating-promises": "error",
        "max-lines-per-function": [
            "warn",
            { max: 200, skipBlankLines: true, skipComments: true }
        ]
    }
};
