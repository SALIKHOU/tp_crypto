from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import flask
import random

app = flask.Flask(__name__)


client_shared_keys={}

# cryptography permet d'effectuer des opéation cryptographyque dans un context réel 

# Ici nous allons l'utiliser pour faire un Key exchange DH 

# g=2 et key_size=2048 lire la document pour connaire la valeur du modulo p en fonction de la taille.
# Il est préférable et fortement conseiller d'utiliser des spécifications données par NIST (ou d'autre orga reconnues)
#parameters = dh.generate_parameters(generator=2, key_size=1024)





# Fonction pour calculer la clé partagée
def calculate_shared_key(public_key: dh.DHPublicKey):
    params = public_key.parameters()
    private_key = params.generate_private_key()
    shared_key = private_key.exchange(public_key)
    server_pubkey_key=private_key.public_key()
    return shared_key, server_pubkey_key

@app.route('/key_exchange', methods=['POST'])
def key_exchange():
    data = flask.request.json
    
    if 'public_key' in data:
        client_public_key = data['public_key']
        #0. Pour calculer la clef partagee, vous devez convertir la clef reçu du format PEM en objet DHPublicKey
        public_pem=client_public_key.encode()
        pubkey = load_pem_public_key(public_pem)
        
        #print(isinstance(pubkey, dh.DHPublicKey))
        
        # Calculer la clé partagée avec la clé publique du client avec clef eu format DHPublicKey 
        shared_key, server_pubkey_key = calculate_shared_key(pubkey)
        

        # Enregistrer la clé partagée avec le client (ne pas inclure dans la réponse)
        #client_shared_keys[flask.request.remote_addr] = shared_key

        
        public_pem_server=server_pubkey_key.public_bytes(encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')
        
        # Imprimer les informations reçues
        print("Client Public Key:", public_pem)
        print("Shared Key (Client):", shared_key)
        return flask.jsonify({'public_key': public_pem_server})
    
    else:
        return flask.jsonify({'error': 'Client public key not found'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=2024,debug=True)
