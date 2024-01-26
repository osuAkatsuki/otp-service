#!/usr/bin/env bash
set -eo pipefail

if [ -z "$APP_COMPONENT" ]; then
  echo "Please set APP_COMPONENT"
  exit 1
fi

if [[ $PULL_SECRETS_FROM_VAULT -eq 1 ]]; then
  # TODO: revert to $APP_ENV
  akatsuki vault get otp-service production-k8s -o .env
  source .env
fi

if [ "$APP_COMPONENT" = "api" ]; then
    exec ./otp-service
else
    echo "Unknown component: $APP_COMPONENT"
    exit 1
fi