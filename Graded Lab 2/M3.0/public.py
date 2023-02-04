from Crypto.PublicKey import ECC

cloud_key = ECC.construct(
    curve="NIST P-256",
    d=23987220175600003505638104238025863320396390917130322116061093214424134413416,
)

cloud_pubkey = cloud_key

carpet_pubkey = ECC.construct(
    curve="NIST P-256",
    point_x=109637990140194192781762668139331656645679619417511154717454882496249980241137,
    point_y=42558765727236481982890227654072802547097323482745689782238599556580059266384,
)

# Test keys for running the server locally.
carpet_test_key = ECC.construct(curve="NIST P-256", d=1337)
cloud_test_key = ECC.construct(curve="NIST P-256", d=0xCAFE)
