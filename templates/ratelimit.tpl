# Rate limit zones for {{DOMAIN}}
limit_req_zone $binary_remote_addr zone={{ZONE_REQ}}:10m rate={{REQ_RATE}};
limit_conn_zone $binary_remote_addr zone={{ZONE_CONN}}:10m;
