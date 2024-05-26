FROM golang:1.21

RUN apt-get update && apt-get install git -y

WORKDIR /srv/root

COPY go.mod go.sum ./
RUN go mod download && go mod verify

RUN apt install -y python3-pip
RUN pip install --break-system-packages git+https://github.com/osuAkatsuki/akatsuki-cli

COPY . /srv/root

RUN git submodule init && git submodule update --remote --recursive --merge

RUN go build

EXPOSE 80

CMD ["./scripts/bootstrap.sh"]
