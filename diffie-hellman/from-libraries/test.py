from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import (
    load_pem_public_key,
    load_pem_private_key
)

# Générer les paramètres DH
parameters = dh.generate_parameters(generator=2, key_size=1024)

# Générer la clé privée du serveur
private_key_server = parameters.generate_private_key()

# Calculer la clé publique du serveur
public_key = private_key_server.public_key()

# Sérialiser la clé privée en PEM sans chiffrement
private_pem = private_key_server.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

print("Private Key:", private_pem)

# Charger la clé privée à partir de PEM
loaded_private_key = load_pem_private_key(private_pem, password=None)
print("Récupération de la clé privée:", isinstance(loaded_private_key, dh.DHPrivateKey))

# Sérialiser la clé publique en PEM
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print("Public Key:", public_pem)

# Charger la clé publique à partir de PEM
loaded_public_key = load_pem_public_key(public_pem)
print("Récupération de la clé publique:", isinstance(loaded_public_key, dh.DHPublicKey))
