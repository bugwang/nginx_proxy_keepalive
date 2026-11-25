# nginx_proxy_keepalive
nginx 的  proxy_pass 命令 不支持 keepalive, 只有upstream 方式才支持，但是upstream 不支持动态域名，所以以此方式实现了proxy_pass 支持keepalive 长链接的基本功能。没有多ngixn版本测试过，懒得测，用的自取

nginx 1.18 [1.30.6] tested 
proxy_pass support keepalive
useage:
*   copy this file to nginx/src/http/  
*   open file : src/http/ngx_http_upstream_round_robin.c
*   #include "proxy_pass_keepalive.h" [ if nginx 1.30.6 #include "proxy_pass_pool.h"]
*   go to function : ngx_http_upstream_create_round_robin_peer 
*   add a line of code in function end :
*   ngx_http_upstream_init_round_robin_keepalive(r,1);  
*   ./configure
*   


<img width="643" height="173" alt="图片" src="https://github.com/user-attachments/assets/4737d686-ed59-4c17-aa3e-c1d06826f623" />


location ~ /proxy/(.*) {
            proxy_next_upstream error;
            proxy_connect_timeout 100ms;
            proxy_send_timeout 100ms;
            proxy_read_timeout   200ms;

            resolver 10.1.0.32 ipv6=off;
            internal;
            rewrite ^/proxy/([^/]+)/(.*)     /$2 break;

            proxy_pass http://$1;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
        }

location /logs/ {
            default_type    text/plain;
            root            /data;
            autoindex       on;
        }
