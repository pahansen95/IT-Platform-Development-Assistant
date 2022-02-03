FROM dperson/samba

RUN mkdir -p /os-imgs && chmod 777 /os-imgs
RUN apk update && apk add curl

COPY ./os-imgs.txt /os-imgs/

RUN cd /os-imgs; xargs -n 1 curl -LO < /os-imgs/os-imgs.txt

ENV TZ=ETC/UTC

CMD [ "-u", "user;password", "-s", "os-imgs;/os-imgs" ]