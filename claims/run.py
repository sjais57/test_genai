if verify_ssl:
    try:
        ssl_certfile, ssl_keyfile = verify_ssl_files()
        
        # Basic SSL context without strict hardening
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(ssl_certfile, ssl_keyfile)
        
        # Only disable the completely broken protocols
        ssl_context.options |= ssl.OP_NO_SSLv2
        ssl_context.options |= ssl.OP_NO_SSLv3
        
    except Exception as e:
        print(f"⚠ SSL configuration failed: {e}")
        ssl_certfile, ssl_keyfile = None, None
