    if config.ssl then
        -- basic flags
        socket_config.ssl = true
        -- default to true unless explicitly false
        socket_config.ssl_verify = (config.ssl_verify ~= false)

        -- NEW: forward extra SSL fields from producer_config (broker_config)
        -- kafka-logger.lua sets ssl_ca_location + ssl_cafile
        socket_config.ssl_ca_location =
            config.ssl_ca_location or config.ssl_cafile

        -- client certificate + key for mTLS
        -- kafka-logger.lua sets ssl_certificate_location/ssl_key_location
        -- and also ssl_cert/ssl_key; accept both.
        socket_config.ssl_certificate_location = config.ssl_certificate_location
        socket_config.ssl_key_location         = config.ssl_key_location

        socket_config.ssl_cert =
            config.ssl_certificate_location or config.ssl_cert
        socket_config.ssl_key  =
            config.ssl_key_location or config.ssl_key

        socket_config.ssl_key_password = config.ssl_key_password

        -- Optional debug log so we see exactly what flows into socket_config
        local ngx_log = ngx and ngx.log
        local INFO    = ngx and ngx.INFO
        if ngx_log and INFO then
            ngx_log(INFO,
                "[kafka-client][debug] new(): SSL enabled, socket_config: ",
                "ssl=", tostring(socket_config.ssl),
                ", ssl_verify=", tostring(socket_config.ssl_verify),
                ", ssl_ca_location=", tostring(socket_config.ssl_ca_location),
                ", ssl_certificate_location=", tostring(socket_config.ssl_certificate_location),
                ", ssl_key_location=", tostring(socket_config.ssl_key_location),
                ", ssl_cert=", tostring(socket_config.ssl_cert),
                ", ssl_key=", tostring(socket_config.ssl_key)
            )
        end
    end
