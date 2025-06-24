FROM node:22-slim AS base

ENV NODE_ENV=development
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable

## DEV STAGE
FROM base as dev

ARG PROJECT_DIR=/src/app/back

RUN pnpm add -g nodemon

USER node
WORKDIR $PROJECT_DIR