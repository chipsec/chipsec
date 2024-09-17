FROM ubuntu:latest@sha256:65a51004dd558ca0bc9ca86f33bd9f2f8e87f94a152aaf76dceeee5a60de0417

RUN apt-get update -y && \
    apt-get install -y python3.8-dev python3.8 python3.8-distutils curl

RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
RUN python3.8 get-pip.py 
copy ./requirements.txt /app/requirements.txt

WORKDIR /app

RUN pip3.8 install -r requirements.txt

COPY . /app

ENV LC_ALL=en_CA.UTF-8
ENV LANG=en_CA.UTF-8
ENV LANGUAGE=en_CA.UTF-8

ENTRYPOINT [ "flask" ]

CMD [ "run", "--host", "0.0.0.0", "--port", "8080"]
