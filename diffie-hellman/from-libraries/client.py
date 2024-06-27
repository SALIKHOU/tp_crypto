from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import requests
# Adresse du serveur Flask
server_address = 'http://127.0.0.1:2024'

# Fonction pour calculer la clé partagée
def calculate_shared_key(sa_public_key: dh.DHPublicKey):
    shared_key = private_key_client.exchange(sa_public_key)
    return shared_key


parameters = dh.generate_parameters(generator=2, key_size=1024)
private_key_client = parameters.generate_private_key()
# Calcul de la clé publique du serveur à partir de sa clé privée
public_key = private_key_client.public_key()
# Convertir la clé publique en une chaine auformat PEM
public_pem=public_key.public_bytes(encoding=serialization.Encoding.PEM,
   format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')
#print(public_pem)
# Données à envoyer au serveur
data = {'public_key': public_pem}
# Envoyer la demande au serveur
response = requests.post(f'{server_address}/key_exchange', json=data)
# Vérifier si la demande a réussi
if response.status_code == 200:
    # Extraire les données de la réponse
    response_data = response.json()
    server_public_key = response_data['public_key']
    serveur_public_pem=server_public_key.encode()
    pubkey = load_pem_public_key(serveur_public_pem)
    shared_key = calculate_shared_key(pubkey)

    # Imprimer les informations reçues
    print("Server Public Key:", public_pem)
    print("Shared Key (Serveur):", shared_key)
else:
    print("Error:", response.text)
