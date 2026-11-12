import security from 'eslint-plugin-security';
export default [security.configs.recommended, { files: ['**/*.mjs'], languageOptions: { ecmaVersion: 2024, sourceType: 'module' } }];
