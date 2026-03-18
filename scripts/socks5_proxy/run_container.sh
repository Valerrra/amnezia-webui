sudo docker run -d \
--restart always \
-p $SOCKS5_PROXY_PORT:$SOCKS5_PROXY_PORT/tcp \
-p $SOCKS5_PROXY_PORT:$SOCKS5_PROXY_PORT/udp \
--name $CONTAINER_NAME \
$CONTAINER_NAME
