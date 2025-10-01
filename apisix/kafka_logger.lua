-- inside schema.properties
ssl = { type = "boolean", default = false },
ssl_verify = { type = "boolean", default = false },
ssl_cafile = { type = "string" },
ssl_cert = { type = "string" },
ssl_key  = { type = "string" },
ssl_protocol = {
    type = "string",
    enum = {"tlsv1", "tlsv1_1", "tlsv1_2", "tlsv1_3"},
    default = "tlsv1_2"
},

-- in _M.log() where broker_config is built:
broker_config["request_timeout"]   = conf.timeout or 1000
broker_config["producer_type"]     = conf.producer_type
broker_config["required_acks"]     = conf.required_acks
broker_config["batch_num"]         = conf.producer_batch_num
broker_config["batch_size"]        = conf.producer_batch_size
broker_config["max_buffering"]     = conf.producer_max_buffering
broker_config["flush_time"]        = (conf.producer_time_linger or -1) * 1000
broker_config["refresh_interval"]  = (conf.meta_refresh_interval or 30) * 1000

-- >>> Add SSL options <<<
if conf.ssl then
    broker_config.ssl = true
    broker_config.ssl_opts = {
        protocol    = conf.ssl_protocol,
        verify      = conf.ssl_verify and "peer" or "none",
        cafile      = conf.ssl_cafile,
        certificate = conf.ssl_cert,
        key         = conf.ssl_key,
    }
end
