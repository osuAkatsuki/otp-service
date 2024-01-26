#!/usr/bin/make

run:
	docker run --network=host --env-file=.env otp-service:latest

build:
	docker build -t otp-service:latest .