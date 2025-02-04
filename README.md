# jibril-api

Client package, types and OpenAPI spec for the API to Jibril Server.

## Spec

The `/spec` directory contains an OpenAPI specification.
You can use it to generate clients for your favorite programming language.
Or preview it using [SwaggerUI](https://editor.swagger.io/?url=https://raw.githubusercontent.com/listen-dev/jibril-api/main/spec/open-api.yml).

### Typescript codegen

Example using [openapi-typescript-codegen](https://www.npmjs.com/package/openapi-typescript-codegen).

```bash
npx openapi-typescript-codegen \
    --input ./spec/open-api.yml \
    --output ./ts-client \
    --name Client
```

### Go codegen

Example using [openapi-codegen](https://github.com/oapi-codegen/oapi-codegen).

```bash
oapi-codegen spec/open-api.yml
```
