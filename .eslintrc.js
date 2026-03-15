module.exports = {
    root: true,
    env: {
        node: true,
        es2021: true,
        jest: true,
    },
    parser: "@typescript-eslint/parser",
    parserOptions: {
        ecmaVersion: "latest",
        sourceType: "module",
    },
    plugins: ["@typescript-eslint", "jest"],
    extends: [
        "eslint:recommended",
        "plugin:@typescript-eslint/recommended",
        "plugin:jest/recommended",
    ],
    rules: {
        "@typescript-eslint/no-unused-vars": ["warn"],
        "@typescript-eslint/no-explicit-any": "off",
    },
    ignorePatterns: ["dist/", "node_modules/"],
};