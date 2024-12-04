FROM ubuntu:latest@sha256:80dd3c3b9c6cecb9f1667e9290b3bc61b78c2678c02cbdae5f0fea92cc6734ab

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
